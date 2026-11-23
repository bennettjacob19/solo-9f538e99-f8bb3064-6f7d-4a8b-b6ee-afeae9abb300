"""TCP 接收窗口诊断分析引擎。

输入：同一连接（同一四元组）的帧序列（按 (ts, id) 升序）。
输出：握手参数、状态事件流、窗口用尽时段。

约定：
- 上传方向（客户端→服务器）为 "fwd"，反向为 "rev"。
- 序号一律换算为相对客户端 ISN 的无符号偏移（mod 2^32）。
  因连接序号跨度 < 2 GiB（2^31），该映射在连接生命周期内无歧义，
  序号回绕由此自然处理。
"""
import bisect

FIN = 0x01
SYN = 0x02
RST = 0x04
ACK = 0x10

MOD32 = 1 << 32
SPAN_LIMIT = 1 << 31  # 2 GiB
MAX_WSCALE = 14       # RFC 7323


class AnalyzeError(Exception):
    """连接不满足可分析条件（无握手 / 双向数据 / 序号跨度过大等）。"""


def _rel(seq: int, isn: int) -> int:
    return (seq - isn) % MOD32


def _opt(row, key):
    """sqlite3.Row 没有 .get；缺列（旧库/普通帧 dict）时返回 None。"""
    try:
        return row[key]
    except (IndexError, KeyError):
        return None


class IntervalSet:
    """已发送字节区间并集（用于在途字节统计，重传只计一次）。"""

    __slots__ = ("iv",)

    def __init__(self):
        self.iv = []  # 有序、互不重叠的 [start, end)

    def add(self, s: int, e: int) -> None:
        if e <= s:
            return
        iv = self.iv
        i = bisect.bisect_left(iv, [s, 0])
        if i > 0 and iv[i - 1][1] >= s:
            i -= 1
        while i < len(iv) and iv[i][0] <= e:
            s = min(s, iv[i][0])
            e = max(e, iv[i][1])
            del iv[i]
        iv.insert(i, [s, e])

    def measure_from(self, x: int) -> int:
        """区间中 >= x 部分的总长度（即确认点为 x 时的在途字节数）。"""
        total = 0
        for s, e in self.iv:
            if e > x:
                total += e - max(s, x)
        return total

    def total(self) -> int:
        return sum(e - s for s, e in self.iv)


def analyze(frames):
    """frames: 按 (ts, id) 排序的 dict 序列，键含
    id, ts, direction('fwd'/'rev'), flags, seq, ack, wnd, payload_len, wscale_opt。

    由 IPv4 分片重组出的段可额外带 frag_ref（使该段凑齐的分片 id）与
    frag_key（分片组键）；此时事件/分界帧以 frag_ref 为准，页面上指向
    实际使报文凑齐的那一帧。

    返回 {meta, events, periods, summary}；不满足条件时抛 AnalyzeError。
    """
    if not frames:
        raise AnalyzeError("所选四元组在捕获中没有任何报文")

    # ---- 定位三次握手 ----
    syn_i = None
    for i, f in enumerate(frames):
        if f["direction"] == "fwd" and (f["flags"] & SYN) and not (f["flags"] & ACK):
            syn_i = i
            break
    if syn_i is None:
        raise AnalyzeError("捕获中未找到客户端 SYN：连接不含握手，无法确定 ISN 与窗口缩放")
    syn = frames[syn_i]

    synack = None
    for f in frames[syn_i + 1 :]:
        if f["direction"] == "rev" and (f["flags"] & SYN) and (f["flags"] & ACK):
            synack = f
            break
    if synack is None:
        raise AnalyzeError("捕获中未找到服务器的 SYN-ACK：握手不完整")

    client_isn = syn["seq"]
    server_isn = synack["seq"]
    cws_opt = syn["wscale_opt"]
    sws_opt = synack["wscale_opt"]
    # RFC 7323：只有 SYN 与 SYN-ACK 都携带 WSCALE 选项时缩放才生效
    scaling = cws_opt is not None and sws_opt is not None
    server_wscale = min(sws_opt, MAX_WSCALE) if scaling else 0
    client_wscale = min(cws_opt, MAX_WSCALE) if scaling else 0

    # ---- 单向性预检 ----
    for f in frames:
        if f["direction"] == "rev" and f["payload_len"] > 0:
            raise AnalyzeError(
                "服务器→客户端方向存在数据载荷：本工具仅分析单向传输的连接"
            )

    # ---- 主模拟 ----
    cum_ack = None        # 累计确认点（相对 ISN）
    wnd = None            # 最新通告窗口（已按服务器 wscale 缩放）
    right_edge = None     # 通告窗口右沿 = cum_ack + wnd
    data_end = 1          # 已发数据末端（SYN 占用序号 0，数据从 1 开始）
    sent = IntervalSet()  # 已发送数据区间并集
    events = []
    last_state = None

    for f in frames[syn_i:]:
        flags = f["flags"]
        if f["direction"] == "fwd":
            if not (flags & SYN):  # SYN（含重传）的序号消耗已计入 ISN 偏移
                plen = f["payload_len"]
                fin = 1 if (flags & FIN) else 0
                if plen or fin:
                    s = _rel(f["seq"], client_isn)
                    e = s + plen + fin
                    if e >= SPAN_LIMIT:
                        raise AnalyzeError(
                            "连接序号跨度达到 2 GiB，超出本工具可分析范围"
                        )
                    if plen:
                        sent.add(s, s + plen)
                    if e > data_end:
                        data_end = e
        else:  # rev：接收方通告
            if flags & ACK:
                a = _rel(f["ack"], client_isn)
                if a >= SPAN_LIMIT:
                    pass  # 明显越界的 ACK（如上一化身残留），忽略
                elif cum_ack is None or a >= cum_ack:
                    cum_ack = a
                    wnd = f["wnd"] << server_wscale
                    right_edge = cum_ack + wnd
                # a < cum_ack：过时 ACK —— 不回退累计确认点，也不更新窗口

        if cum_ack is not None:
            inflight = sent.measure_from(cum_ack)
            margin = right_edge - max(cum_ack, data_end)
            state = (cum_ack, data_end, right_edge, margin, inflight)
            if state != last_state:
                events.append(
                    {
                        "ts": f["ts"],
                        "frame_id": f["id"],
                        "frag_ref": _opt(f, "frag_ref"),
                        "cum_ack": cum_ack,
                        "data_end": data_end,
                        "right_edge": right_edge,
                        "margin": margin,
                        "inflight": inflight,
                    }
                )
                last_state = state

    if not events:
        raise AnalyzeError("握手之后没有任何可用的 ACK/数据报文，无法形成诊断")

    # ---- 窗口用尽时段（余量 <= 0）及分界帧 ----
    periods = []
    cur = None
    for ev in events:
        if ev["margin"] <= 0:
            if cur is None:
                cur = {
                    "start_ts": ev["ts"],
                    "start_frame": ev["frame_id"],
                    "start_frag_ref": ev["frag_ref"],
                    "min_margin": ev["margin"],
                }
            elif ev["margin"] < cur["min_margin"]:
                cur["min_margin"] = ev["margin"]
        else:
            if cur is not None:
                cur["end_ts"] = ev["ts"]
                cur["end_frame"] = ev["frame_id"]
                cur["end_frag_ref"] = ev["frag_ref"]
                periods.append(cur)
                cur = None
    if cur is not None:  # 捕获结束时仍在用尽状态
        cur["end_ts"] = None
        cur["end_frame"] = None
        cur["end_frag_ref"] = None
        periods.append(cur)

    first_ts = frames[0]["ts"]
    last_ts = frames[-1]["ts"]
    exhausted_ns = 0
    for p in periods:
        exhausted_ns += (p["end_ts"] if p["end_ts"] is not None else last_ts) - p["start_ts"]

    meta = {
        "client_isn": client_isn,
        "server_isn": server_isn,
        "client_wscale_opt": cws_opt,
        "server_wscale_opt": sws_opt,
        "client_wscale": client_wscale,
        "server_wscale": server_wscale,
        "scaling": scaling,
    }
    summary = {
        "first_ts": first_ts,
        "last_ts": last_ts,
        "conn_frames": len(frames),
        "total_data_bytes": sent.total(),
        "max_inflight": max(ev["inflight"] for ev in events),
        "min_margin": min(ev["margin"] for ev in events),
        "exhausted_periods": len(periods),
        "exhausted_ns": exhausted_ns,
    }
    return {"meta": meta, "events": events, "periods": periods, "summary": summary}
