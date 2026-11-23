"""经典 PCAP（Ethernet / IPv4 / TCP）纯 Python 解析。

只依赖标准库，解析结果供分析引擎使用。
"""
import socket
import struct

LINKTYPE_ETHERNET = 1

_ETHERTYPE_IPV4 = 0x0800
_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)

_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),  # little-endian, 微秒
    b"\xa1\xb2\xc3\xd4": (">", 1000),  # big-endian, 微秒
    b"\x4d\x3c\xb2\xa1": ("<", 1),     # little-endian, 纳秒
    b"\xa1\xb2\x3c\x4d": (">", 1),     # big-endian, 纳秒
}

MAX_RECORD_LEN = 16 * 1024 * 1024


class PcapError(Exception):
    """PCAP 文件本身无法解析。"""


def parse_pcap(data: bytes):
    """产出 (ts_ns, raw_frame_bytes)。ts_ns 为 UTC 纳秒时间戳。"""
    if len(data) < 24:
        raise PcapError("文件太小，不是有效的 PCAP 文件")
    magic = data[:4]
    if magic not in _MAGICS:
        if magic in (b"\x0a\x0d\x0d\x0a",):
            raise PcapError("检测到 pcapng 格式，本工具仅支持经典 PCAP")
        raise PcapError("无法识别的 PCAP 魔数，仅支持经典 PCAP 格式")
    endian, frac_mul = _MAGICS[magic]
    _magic, _vmaj, _vmin, _tz, _sig, _snap, network = struct.unpack(
        endian + "IHHIIII", data[:24]
    )
    if network != LINKTYPE_ETHERNET:
        raise PcapError(f"数据链路类型 {network} 不受支持，仅支持以太网（Ethernet）抓包")
    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack_from(
            endian + "IIII", data, off
        )
        off += 16
        if incl_len > MAX_RECORD_LEN or off + incl_len > n:
            raise PcapError("报文记录长度异常，文件可能已损坏")
        raw = data[off : off + incl_len]
        off += incl_len
        yield ts_sec * 1_000_000_000 + ts_frac * frac_mul, raw
    # 尾部不足一条记录的字节视为容忍（部分抓包工具会留下截断尾）


def parse_frame(raw: bytes):
    """解析一帧以太网报文。

    返回 dict（IPv4+TCP）或 None（非 IPv4/TCP、分片、截断等）。
    """
    if len(raw) < 14:
        return None
    eth_type = struct.unpack_from("!H", raw, 12)[0]
    off = 14
    # 跳过最多两层 VLAN 标签
    for _ in range(2):
        if eth_type not in _VLAN_TYPES:
            break
        if len(raw) < off + 4:
            return None
        eth_type = struct.unpack_from("!H", raw, off + 2)[0]
        off += 4
    if eth_type != _ETHERTYPE_IPV4:
        return None
    if len(raw) < off + 20:
        return None
    vihl = raw[off]
    if vihl >> 4 != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(raw) < off + ihl:
        return None
    total_len = struct.unpack_from("!H", raw, off + 2)[0]
    frag = struct.unpack_from("!H", raw, off + 6)[0]
    if frag & 0x3FFF:  # MF 置位或片偏移非零：分片报文无法还原 TCP，跳过
        return None
    if raw[off + 9] != 6:  # 非 TCP
        return None
    src_ip = socket.inet_ntoa(raw[off + 12 : off + 16])
    dst_ip = socket.inet_ntoa(raw[off + 16 : off + 20])
    tcp_off = off + ihl
    if len(raw) < tcp_off + 20:
        return None
    sport, dport, seq, ack, off_flags, wnd, _csum, _urg = struct.unpack_from(
        "!HHIIHHHH", raw, tcp_off
    )
    data_off = (off_flags >> 12) * 4
    flags = off_flags & 0x1FF
    if data_off < 20 or len(raw) < tcp_off + data_off:
        return None
    if total_len < ihl + data_off:
        return None
    payload_len = total_len - ihl - data_off  # 以 IP 总长度为准（抓包截断时仍反映线上长度）

    wscale_opt = None
    opts = raw[tcp_off + 20 : tcp_off + data_off]
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        olen = opts[i + 1]
        if olen < 2 or i + olen > len(opts):
            break
        if kind == 3 and olen == 3:
            wscale_opt = opts[i + 2]
        i += olen

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": sport,
        "dst_port": dport,
        "seq": seq,
        "ack": ack,
        "flags": flags,
        "wnd": wnd,
        "payload_len": payload_len,
        "wscale_opt": wscale_opt,
    }
