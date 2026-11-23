"""IPv4 分片重组：把上传方向的分片还原为可分析的 TCP 段。

约定（与需求一致）：
- 只处理客户端→服务器方向的分片报文；反向分片直接忽略。
- 首片必须包含**完整** TCP 头，凭其中的四元组确认该分片组是否属于所选连接；
  非首片没有端口信息，先保留，待首片到达后再决定是否计入。
- 同一 (源地址, 目的地址, IP ID) 下的分片组：除同一分片的副本外，各片不重叠。
- 段的时间取**原抓包时间**：每个分片取所有副本中最早的时间，所有分片到齐的
  最晚时刻即"首次凑齐"的时刻；若据此进入窗口用尽，分界帧指向使报文凑齐的分片。
  因此后补入时间戳更早的副本可以让报文提前凑齐，需整体重算。
"""
import hashlib
import struct

from pcaputil import parse_tcp_options


class FragmentError(Exception):
    """分片流违反单连接分析约定（重叠、内容冲突、头不完整等）。"""


def group_key(src_ip: str, dst_ip: str, ip_id: int) -> str:
    """分片组键：同一对源/目的地址之间 IP ID 不复用。"""
    return f"{src_ip}>{dst_ip}#{ip_id}"


def fragment_hash(data: bytes, offset: int, src_ip: str, dst_ip: str, ip_id: int) -> str:
    """单个分片（同一副本）的内容摘要。

    含分片组键与偏移，避免同一时间戳上不同 IP ID / 不同偏移的同内容
    片段被误判为副本：分片表的 UNIQUE(session_id, ts, hash) 因此恰好
    只把「同一分片组的同一副本」视为重复。
    """
    h = hashlib.blake2b(digest_size=16)
    h.update(group_key(src_ip, dst_ip, ip_id).encode())
    h.update(b"\0")
    h.update(struct.pack("!I", offset))
    h.update(data)
    return h.hexdigest()


def parse_tcp_header(data: bytes):
    """data 从 IP 载荷起点开始；只在完整 TCP 头都已抓到时返回解析结果。"""
    if len(data) < 20:
        return None
    sport, dport, seq, ack, off_flags, wnd, _csum, _urg = struct.unpack_from(
        "!HHIIHHHH", data
    )
    hdr_len = (off_flags >> 12) * 4
    if hdr_len < 20 or len(data) < hdr_len:
        return None
    return {
        "src_port": sport,
        "dst_port": dport,
        "seq": seq,
        "ack": ack,
        "flags": off_flags & 0x1FF,
        "wnd": wnd,
        "hdr_len": hdr_len,
        "wscale_opt": parse_tcp_options(data[20:hdr_len]),
    }


def reassemble(rows, client_port, server_port, key=None):
    """重组一个分片组。

    rows: 同一分片组的片段记录（按到达顺序即行 id 升序），
          键含 id, ts, offset, mf, frag_len, data, hash, capture_no, upload_id。

    返回 dict：
      state         'tentative'（首片未知/头不完整）/'owned'/'rejected'（非本连接）
      complete      结构上是否已凑齐
      payload_len   重组出的 IP 载荷长度（TCP 头 + 数据），未凑齐为 None
      ts            段首次凑齐的原抓包时间（纳秒），未凑齐为 None
      completing_id 使报文凑齐的分片行 id
      hash          重组内容摘要
      frame         可入库的 TCP 段（仅 owned 且完整时），字段同普通帧
    """
    rows = list(rows)
    out = {
        "state": "tentative",
        "complete": False,
        "payload_len": None,
        "ts": None,
        "completing_id": None,
        "hash": None,
        "frame": None,
    }
    if not rows:
        return out

    # 首片必须含完整 TCP 头：它同时确定连接归属与段头。
    # 抓包截断的首片不算「含完整头」，继续等待另一份完整副本。
    h0 = None
    for r in rows:
        if r["offset"] != 0:
            continue
        parsed = parse_tcp_header(bytes(r["data"]))
        if parsed is not None:
            if h0 is not None and (parsed["src_port"], parsed["dst_port"]) != (
                h0["src_port"], h0["dst_port"]
            ):
                raise FragmentError("同一分片组的首片端口不一致，无法确认连接归属")
            if h0 is None:
                h0 = parsed
    if h0 is None:
        return out  # 尚未见到含完整 TCP 头的首片，归属与段头都未知

    owned = (h0["src_port"], h0["dst_port"]) == (client_port, server_port)
    out["state"] = "owned" if owned else "rejected"

    by_off = {}
    for r in rows:
        data = bytes(r["data"])
        if len(data) != r["frag_len"]:
            continue
        off = r["offset"]
        cur = by_off.get(off)
        if cur is None:
            by_off[off] = {
                "offset": off,
                "frag_len": r["frag_len"],
                "mf": r["mf"],
                "data": data,
                "hash": r["hash"],
                "rows": [r],
            }
        else:
            if cur["hash"] != r["hash"] or cur["mf"] != r["mf"]:
                raise FragmentError(
                    f"偏移 {off} 上的分片出现内容不同的副本，无法唯一重组"
                )
            cur["rows"].append(r)

    if not owned:
        return out  # 不属于所选连接：保留原始分片，但不参与本连接诊断

    pieces = sorted(by_off.values(), key=lambda p: p["offset"])
    if not pieces or pieces[0]["offset"] != 0:
        return out  # 首片尚未到达（或首片被截断，无法重组）

    # ---- 结构检查：同一分片组只允许一个末片；各片不得重叠；
    #      允许暂时有空洞（分次上传） ----
    gap = False
    prev_end = 0
    last = None
    for p in pieces:
        if p["offset"] < prev_end:
            raise FragmentError("分片区间重叠：除同一分片的副本外各片不得重叠")
        if p["offset"] > prev_end:
            gap = True
        prev_end = p["offset"] + p["frag_len"]
        if p["mf"] == 0:
            if last is not None:
                raise FragmentError("同一分片组出现多个末片（MF=0）")
            last = p
    if last is None:
        return out  # 尚未见到末片，长度未知
    if last is not pieces[-1]:
        raise FragmentError("末片之后仍有分片，分片组不完整或已损坏")

    end = last["offset"] + last["frag_len"]
    complete = not gap and prev_end == end

    out["payload_len"] = end - h0["hdr_len"]
    if out["payload_len"] < 0:
        raise FragmentError("首片不足以容纳声明的 TCP 头，分片组已损坏")

    if not complete:
        return out

    # ---- 按原抓包时间确定"首次凑齐"的时刻 ----
    # 每个偏移取所有副本中最早的时间；末片到达的时刻即整段首次凑齐的时刻。
    # 补入时间更早的副本可能把 max 推到别的分片上，从而整体提前。
    for p in pieces:
        best = min(p["rows"], key=lambda r: (r["ts"], r["id"]))
        p["ts"] = best["ts"]
        p["best"] = best
    comp = max(pieces, key=lambda p: (p["ts"], p["best"]["id"]))
    out["complete"] = True
    out["ts"] = comp["ts"]
    out["completing_id"] = comp["best"]["id"]

    payload = b"".join(p["data"] for p in pieces)
    h = hashlib.blake2b(digest_size=16)
    h.update(b"FRAG")
    h.update((key or group_key(rows[0]["src_ip"], rows[0]["dst_ip"],
                               rows[0]["ip_id"])).encode())
    h.update(payload)
    out["hash"] = h.hexdigest()

    crow = comp["best"]
    out["frame"] = {
        "ts": comp["ts"],
        "hash": out["hash"],
        "direction": "fwd",
        "flags": h0["flags"],
        "seq": h0["seq"],
        "ack": h0["ack"],
        "wnd": h0["wnd"],
        "payload_len": out["payload_len"],
        "wscale_opt": h0["wscale_opt"],
        "capture_no": crow["capture_no"],
        "upload_id": crow["upload_id"],
        "frag_ref": crow["id"],
        "frag_key": key or group_key(
            rows[0]["src_ip"], rows[0]["dst_ip"], rows[0]["ip_id"]
        ),
    }
    return out
