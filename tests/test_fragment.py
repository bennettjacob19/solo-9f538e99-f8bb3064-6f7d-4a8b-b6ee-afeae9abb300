"""IPv4 分片重组 + 上传/补传端到端测试。"""
import os
import sqlite3
import struct
import sys
import tempfile
import unittest
from io import BytesIO
from socket import inet_aton

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402

C_IP, S_IP = "10.0.0.1", "10.0.0.2"
C_PORT, S_PORT = 50000, 443
C_ISN, S_ISN = 100_000, 900_000
BASE_S = 1_780_000_000

SYN, ACK, FIN, PSH = 0x02, 0x10, 0x01, 0x08

ETH = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"


def ms(n):
    return BASE_S * 1_000_000_000 + n * 1_000_000


def tcp_segment(src, dst, sport, dport, seq, ack, flags, wnd,
                payload=b"", wscale=None):
    opts = b""
    if wscale is not None:
        opts = bytes([3, 3, wscale, 1])
    pad = (-len(opts)) % 4
    opts += b"\x00" * pad
    doff = 5 + len(opts) // 4
    return struct.pack(
        "!HHIIHHHH", sport, dport, seq, ack, (doff << 12) | flags, wnd, 0, 0
    ) + opts + payload


def ip_packet(src, dst, payload, ip_id=0x1234, offset=0, mf=0):
    total = 20 + len(payload)
    frag = (0x2000 if mf else 0) | (offset // 8)
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, ip_id, frag, 64, 6, 0,
        inet_aton(src), inet_aton(dst),
    ) + payload


def plain_frame(src, dst, sport, dport, seq, ack, flags, wnd,
                payload_len=0, wscale=None, ip_id=0x1234):
    seg = tcp_segment(src, dst, sport, dport, seq, ack, flags, wnd,
                      b"\x61" * payload_len, wscale)
    return ETH + ip_packet(src, dst, seg, ip_id=ip_id)


def frag_frames(src, dst, sport, dport, seq, ack, flags, wnd,
                payload_len, mtu_payload=1000, ip_id=7, t0=0,
                cuts=None, order=None):
    """把 TCP 段切成 IPv4 分片，返回 [(ts, raw_frame, 分片序号), ...]。

    t0 为第一片时间偏移（ms），各片依次间隔 1ms；order 可重排到达顺序。
    cuts 指定切点（相对 TCP 段起点的字节偏移，须为 8 的倍数）；
    省略时按 mtu_payload 向下取 8 的倍数自动切分。
    """
    seg = tcp_segment(src, dst, sport, dport, seq, ack, flags, wnd,
                      b"\x61" * payload_len)
    if cuts is None:
        step = (mtu_payload // 8) * 8
        cuts = list(range(step, len(seg), step))
    bounds = [0] + list(cuts) + [len(seg)]
    slices = [seg[a:b] for a, b in zip(bounds, bounds[1:]) if b > a]
    frames = []
    for i, chunk in enumerate(slices):
        off = bounds[i]
        assert off % 8 == 0
        mf = 1 if i < len(slices) - 1 else 0
        pkt = ETH + ip_packet(src, dst, chunk, ip_id=ip_id, offset=off, mf=mf)
        frames.append((ms(t0 + i), pkt, i))
    if order is not None:
        frames = [frames[i] for i in order]
    return frames


def c2s(seq, ack, flags, wnd=2000, payload_len=0, wscale=None, ip_id=0x1234):
    return plain_frame(C_IP, S_IP, C_PORT, S_PORT, C_ISN + seq, ack, flags, wnd,
                       payload_len, wscale, ip_id)


def s2c(seq, ack, flags, wnd, wscale=None, payload_len=0):
    return plain_frame(S_IP, C_IP, S_PORT, C_PORT, S_ISN + seq, ack, flags, wnd,
                       payload_len, wscale)


def build_pcap(frames):
    out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for item in frames:
        ts, raw = item[0], item[1]
        sec, ns = divmod(ts, 1_000_000_000)
        out.append(struct.pack("<IIII", sec, ns // 1000, len(raw), len(raw)))
        out.append(raw)
    return b"".join(out)


def handshake(wscale_c=2, wscale_s=2, wnd_s=1000):
    return [
        (ms(0), c2s(0, 0, SYN, wscale=wscale_c)),
        (ms(1), s2c(0, C_ISN + 1, SYN | ACK, wnd_s, wscale=wscale_s)),
        (ms(2), c2s(1, S_ISN + 1, ACK)),
    ]


class FragmentTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.app = create_app({"DB_PATH": self.db_path, "TESTING": True})
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    # ---- 辅助 ----
    def post_analyze(self, frames):
        data = {
            "client_ip": C_IP, "client_port": str(C_PORT),
            "server_ip": S_IP, "server_port": str(S_PORT),
            "pcap": (BytesIO(build_pcap(frames)), "cap.pcap"),
        }
        return self.client.post("/analyze", data=data, follow_redirects=False)

    def post_supplement(self, sid, frames, name="frag.pcap"):
        return self.client.post(
            f"/session/{sid}/supplement",
            data={"pcap": (BytesIO(build_pcap(frames)), name)},
            follow_redirects=False,
        )

    def db(self, sql, args=()):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def version(self, sid=1):
        return self.db("SELECT current_version v FROM sessions WHERE id=?", (sid,))[0]["v"]

    def periods(self, sid=1):
        return self.db(
            "SELECT * FROM periods WHERE session_id=? AND version=? ORDER BY idx",
            (sid, self.version(sid)),
        )

    def event_at(self, ts, sid=1):
        rows = self.db(
            "SELECT * FROM events WHERE session_id=? AND version=? AND ts<=?"
            " ORDER BY ts DESC, idx DESC LIMIT 1",
            (sid, self.version(sid), ts),
        )
        return rows[0] if rows else None

    def session_row(self, sid=1):
        return self.db("SELECT * FROM sessions WHERE id=?", (sid,))[0]

    # ---- 场景 ----
    def test_fragmented_data_used_for_window_exhaustion(self):
        """分片数据段重组后计入诊断；窗口用尽的分界帧指向凑齐分片。"""
        f = handshake()
        # 2 个分片组成 2000B 段，末端 2001；右沿 4001 → 有余量
        frags = frag_frames(C_IP, S_IP, C_PORT, S_PORT,
                            C_ISN + 1, S_ISN + 1, ACK | PSH, 2000,
                            payload_len=2000, cuts=[1000], ip_id=42, t0=3)
        self.assertEqual(len(frags), 2)
        f.extend((ts, raw) for ts, raw, _ in frags)
        # 其余 2000B 用普通帧把窗口填满（t=8），再进用尽（t=9）
        f.append((ms(8), c2s(2001, S_ISN + 1, ACK | PSH, payload_len=1000)))
        f.append((ms(9), c2s(3001, S_ISN + 1, ACK | PSH, payload_len=1000)))
        r = self.post_analyze(f)
        self.assertEqual(r.status_code, 302, r.data[:300])
        s = self.session_row()
        self.assertEqual(s["status"], "ok", s["error"])

        # 两片 t=3、t=4 首次凑齐 → 该段计入 t=4ms；末端 4001 时用尽
        self.assertEqual(self.event_at(ms(5))["inflight"], 2000)
        self.assertEqual(s["total_data_bytes"], 4000)
        ps = self.periods()
        self.assertEqual(len(ps), 1)
        self.assertEqual(ps[0]["start_ts"], ms(9))
        self.assertEqual(ps[0]["min_margin"], 0)

        # 重传同一分片组（副本）：诊断版本与帧数不变
        ver = self.version()
        self.post_supplement(1, [(ts, raw) for ts, raw, _ in frags])
        self.assertEqual(self.version(), ver)
        up = self.db("SELECT * FROM uploads ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual((up["status"], up["fragments_added"], up["fragments_dup"]),
                         ("ok", 0, 2))

    def test_fragment_completion_enters_exhaustion(self):
        """分片凑齐使窗口用尽时，分界帧指向使报文凑齐的分片。"""
        f = handshake()
        f.append((ms(3), c2s(1, S_ISN + 1, ACK | PSH, payload_len=3000)))
        # 补一个 1000B 的分片段（两片），末端 4001 → 用尽
        frags = frag_frames(C_IP, S_IP, C_PORT, S_PORT,
                            C_ISN + 3001, S_ISN + 1, ACK | PSH, 2000,
                            payload_len=1000, cuts=[1000], ip_id=43, t0=10)
        f.extend((ts, raw) for ts, raw, _ in frags)
        self.post_analyze(f)
        ps = self.periods()
        self.assertEqual(len(ps), 1)
        self.assertEqual(ps[0]["start_ts"], ms(11))
        # 分界帧指向 t=11ms 的末片
        frag = self.db("SELECT * FROM fragments WHERE id=?",
                       (ps[0]["start_frag_ref"],))[0]
        self.assertEqual((frag["ts"], frag["offset"]), (ms(11), 1000))

    def test_all_frags_in_one_upload_and_frame_pointer(self):
        """整份上传中分片首次凑齐即计入；分界帧标识为凑齐分片。"""
        f = handshake()
        # 先发 2000B（末端 2001，余量 2000），再由分片段把末端推到 4001
        f.append((ms(3), c2s(1, S_ISN + 1, ACK | PSH, payload_len=1000)))
        f.append((ms(4), c2s(1001, S_ISN + 1, ACK | PSH, payload_len=1000)))
        frags = frag_frames(C_IP, S_IP, C_PORT, S_PORT,
                            C_ISN + 2001, S_ISN + 1, ACK | PSH, 2000,
                            payload_len=2000, cuts=[1000], ip_id=99, t0=5)
        self.assertEqual(len(frags), 2)
        f.extend((ts, raw) for ts, raw, _ in frags)
        self.post_analyze(f)
        s = self.session_row()
        self.assertEqual(s["status"], "ok", s["error"])
        ps = self.periods()
        self.assertEqual(len(ps), 1)
        # 两片在 t=5、t=6，首次凑齐 = t=6ms（右沿 4001，末端 4001）
        self.assertEqual(ps[0]["start_ts"], ms(6))
        frag = self.db("SELECT * FROM fragments WHERE id=?",
                       (ps[0]["start_frag_ref"],))[0]
        self.assertEqual(frag["ts"], ms(6))

    def test_non_head_first_and_later_head_applies(self):
        """非首片先到也保留；首片到达后确认归属并计入。"""
        f = handshake(wnd_s=1000)
        self.post_analyze(f)
        frags = frag_frames(C_IP, S_IP, C_PORT, S_PORT,
                            C_ISN + 1, S_ISN + 1, ACK | PSH, 1000,
                            payload_len=3000, cuts=[1000, 2000], ip_id=5, t0=4)
        # 先只传非首片（末片违纪最先行）：组仍 tentative，未产生段
        self.post_supplement(1, [(ts, raw) for ts, raw, i in reversed(frags) if i != 0])
        self.assertEqual(len(self.db("SELECT * FROM fragments WHERE session_id=1")),
                         len(frags) - 1)
        self.assertEqual(self.event_at(ms(20))["inflight"], 0)
        # 补首片 → 归属确认，整段计入
        self.post_supplement(1, [(ts, raw) for ts, raw, _ in frags if _ == 0])
        ev = self.event_at(ms(20))
        self.assertEqual(ev["inflight"], 3000)

    def test_out_of_connection_fragment_rejected_by_head(self):
        """非首片先到但首片显示是别的连接 → 该组不作为本连接段。"""
        f = handshake()
        self.post_analyze(f)
        frags = frag_frames("10.0.0.9", S_IP, 44444, S_PORT,
                            C_ISN + 1, S_ISN + 1, ACK | PSH, 2000,
                            payload_len=3000, cuts=[1000, 2000], ip_id=8, t0=4)
        self.post_supplement(1, [(ts, raw) for ts, raw, _ in frags])
        # 首片确认四元组不符 → 不计入
        self.assertEqual(self.event_at(ms(20))["inflight"], 0)
        self.assertEqual(self.session_row()["status"], "ok")

    def test_reverse_direction_fragment_ignored(self):
        """反向分片不处理（只处理上传方向）。"""
        f = handshake()
        frags = frag_frames(S_IP, C_IP, S_PORT, C_PORT,
                            S_ISN + 1, C_ISN + 1, ACK, 1000,
                            payload_len=3000, cuts=[1000, 2000], ip_id=9, t0=4)
        f.extend((ts, raw) for ts, raw, _ in frags)
        self.post_analyze(f)
        self.assertEqual(len(self.db("SELECT * FROM fragments WHERE session_id=1")), 0)
        self.assertEqual(self.session_row()["status"], "ok")

    def test_earlier_copy_makes_earlier_completion(self):
        """补入原抓包时间更早的副本使报文提前凑齐 → 后续时段/时点查询纠正。"""
        f = handshake(wnd_s=1000)
        # 两片组成 2000B 数据段（TCP 头 20B + 1980B 数据）：首片 t=10、末片 t=11
        seg_frames = frag_frames(C_IP, S_IP, C_PORT, S_PORT,
                                 C_ISN + 1, S_ISN + 1, ACK | PSH, 2000,
                                 payload_len=1980, cuts=[1000], ip_id=21, t0=10)
        self.assertEqual(len(seg_frames), 2)
        f.extend((ts, raw) for ts, raw, _ in seg_frames)
        self.post_analyze(f)
        # 原抓包：首片 t=10、末片 t=11 → 段首次凑齐于 t=11
        self.assertEqual(self.event_at(ms(10) + 500_000)["inflight"], 0)
        self.assertEqual(self.event_at(ms(11) + 500_000)["inflight"], 1980)

        # 补入末片的一份更早副本（原抓包时间 t=9ms）→ 凑齐提前到 t=10ms
        last = [x for x in seg_frames if x[2] == 1][0]
        self.post_supplement(1, [(ms(9), last[1])])
        # t=9.5ms 仍未凑齐（首片 t=10 尚未到达）
        self.assertEqual(self.event_at(ms(9) + 500_000)["inflight"], 0)
        # t=10.5ms 已凑齐（此前是 0）→ 时点查询随之纠正
        self.assertEqual(self.event_at(ms(10) + 500_000)["inflight"], 1980)

    def test_overlap_and_conflict_reject_entire_supplement(self):
        """分片重叠：整份补传回滚，新增分片不入库，原诊断可查。"""
        f = handshake(wnd_s=1000)
        frags = frag_frames(C_IP, S_IP, C_PORT, S_PORT,
                            C_ISN + 1, S_ISN + 1, ACK | PSH, 1000,
                            payload_len=1980, mtu_payload=1000, ip_id=3, t0=4)
        f.extend((ts, raw) for ts, raw, _ in frags)
        self.post_analyze(f)
        ver = self.version()
        n_frag = len(self.db("SELECT * FROM fragments WHERE session_id=1"))

        # 构造一个与已有首片重叠且内容不同的分片（偏移 0 -> 但更短，MF 仍置位）
        seg = tcp_segment(C_IP, S_IP, C_PORT, S_PORT,
                          C_ISN + 1, S_ISN + 1, ACK | PSH, 1000, b"\x62" * 400)
        pkt = ETH + ip_packet(C_IP, S_IP, seg[:200], ip_id=3, offset=0, mf=1)
        r = self.post_supplement(1, [(ms(50), pkt)])
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.session_row()["status"], "ok")
        self.assertEqual(self.version(), ver)  # 未生成新版本
        self.assertEqual(
            len(self.db("SELECT * FROM fragments WHERE session_id=1")), n_frag)
        up = self.db("SELECT * FROM uploads ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(up["status"], "failed")

    def test_truncated_head_not_counted(self):
        """抓包截断的首片无法给出完整 TCP 头 → 该组不计入。"""
        f = handshake(wnd_s=1000)
        self.post_analyze(f)
        seg = tcp_segment(C_IP, S_IP, C_PORT, S_PORT,
                          C_ISN + 1, S_ISN + 1, ACK | PSH, 1000, b"\x61" * 3000)
        # 首片只抓到头 10 字节（IP 声明长度很大）
        head = ETH + ip_packet(C_IP, S_IP, seg[:10], ip_id=77, offset=0, mf=1)
        # 手工放大 IP 总长度，令其声明载荷 1000B，但实际只有 10B
        head = head[:16] + struct.pack("!H", 20 + 1000) + head[18:]
        tail = ETH + ip_packet(C_IP, S_IP, seg[1000:], ip_id=77, offset=1000, mf=0)
        self.post_supplement(1, [(ms(4), head), (ms(5), tail)])
        self.assertEqual(self.event_at(ms(20))["inflight"], 0)

    def test_supported_via_docker_compose(self):
        """docker compose 配置存在且 Dockerfile 拷贝新增模块。"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "Dockerfile"), encoding="utf-8") as fh:
            dockerfile = fh.read()
        self.assertIn("fragment.py", dockerfile)
        with open(os.path.join(root, "docker-compose.yml"), encoding="utf-8") as fh:
            compose = fh.read()
        self.assertIn("8000:8000", compose)


if __name__ == "__main__":
    unittest.main()
