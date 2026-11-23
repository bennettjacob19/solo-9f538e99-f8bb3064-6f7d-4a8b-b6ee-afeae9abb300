"""核心场景测试：合成 PCAP -> Flask test_client -> 断言诊断结果。"""
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
BASE_S = 1_780_000_000  # 固定 epoch 基准

SYN, ACK, FIN, PSH = 0x02, 0x10, 0x01, 0x08


def ms(n):
    return BASE_S * 1_000_000_000 + n * 1_000_000


def tcp_frame(src, dst, sport, dport, seq, ack, flags, wnd, payload_len=0, wscale=None):
    opts = b""
    if wscale is not None:
        opts = bytes([3, 3, wscale, 1])  # WSCALE(3B) + NOP
    doff = 5 + len(opts) // 4
    tcp = struct.pack(
        "!HHIIHHHH", sport, dport, seq, ack, (doff << 12) | flags, wnd, 0, 0
    ) + opts + b"\x61" * payload_len
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x1234, 0, 64, 6, 0,
        inet_aton(src), inet_aton(dst),
    )
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    return eth + ip + tcp


def c2s(seq, ack, flags, wnd=2000, payload_len=0, wscale=None, isn=None):
    return tcp_frame(C_IP, S_IP, C_PORT, S_PORT,
                     (isn if isn is not None else C_ISN) + seq, ack, flags, wnd,
                     payload_len, wscale)


def s2c(seq, ack, flags, wnd, wscale=None, payload_len=0, isn=None):
    return tcp_frame(S_IP, C_IP, S_PORT, C_PORT,
                     (isn if isn is not None else S_ISN) + seq, ack, flags, wnd,
                     payload_len, wscale)


def build_pcap(frames):
    out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for ts, raw in frames:
        sec, ns = divmod(ts, 1_000_000_000)
        out.append(struct.pack("<IIII", sec, ns // 1000, len(raw), len(raw)))
        out.append(raw)
    return b"".join(out)


def handshake_frames(wscale_c=2, wscale_s=2, wnd_s=1000, c_isn=C_ISN, s_isn=S_ISN):
    return [
        (ms(0), c2s(0, 0, SYN, wscale=wscale_c, isn=c_isn)),
        (ms(1), s2c(0, c_isn + 1, SYN | ACK, wnd_s, wscale=wscale_s, isn=s_isn)),
        (ms(2), c2s(1, s_isn + 1, ACK, isn=c_isn)),
    ]


def scenario_stall():
    """握手(wscale=2, 服务器通告1000→缩放4000) + 填满窗口 + 重传 + 过时ACK。"""
    f = handshake_frames()
    # t=3..6ms：客户端发 4×1000B，rel 1..4001，右沿=1+4000=4001 → t=6ms 用尽
    for i in range(4):
        f.append((ms(3 + i), c2s(1 + i * 1000, S_ISN + 1, ACK | PSH, payload_len=1000)))
    f.append((ms(10), c2s(1001, S_ISN + 1, ACK | PSH, payload_len=1000)))  # 重传
    f.append((ms(20), s2c(2001, C_ISN + 2001, ACK, 1000)))                # 窗口打开
    f.append((ms(25), s2c(1500, C_ISN + 500, ACK, 1)))                    # 过时 ACK
    f.append((ms(30), c2s(4001, S_ISN + 1, ACK | PSH, payload_len=1000)))
    f.append((ms(31), c2s(5001, S_ISN + 1, ACK | PSH, payload_len=1000)))  # 再次用尽
    f.append((ms(40), s2c(4001, C_ISN + 6001, ACK, 1000)))                # 全部确认
    return f


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.app = create_app({"DB_PATH": self.db_path, "TESTING": True})
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    # ---- 辅助 ----
    def post_analyze(self, frames, **kw):
        data = {
            "client_ip": kw.get("client_ip", C_IP),
            "client_port": str(kw.get("client_port", C_PORT)),
            "server_ip": kw.get("server_ip", S_IP),
            "server_port": str(kw.get("server_port", S_PORT)),
            "pcap": (BytesIO(build_pcap(frames)), "cap.pcap"),
        }
        return self.client.post("/analyze", data=data, follow_redirects=False)

    def post_supplement(self, session_id, frames, name="frag.pcap"):
        return self.client.post(
            f"/session/{session_id}/supplement",
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

    def periods(self, sid=1):
        s = self.db("SELECT current_version v FROM sessions WHERE id=?", (sid,))[0]
        return self.db(
            "SELECT * FROM periods WHERE session_id=? AND version=? ORDER BY idx",
            (sid, s["v"]),
        )

    def event_at(self, ts, sid=1):
        s = self.db("SELECT current_version v FROM sessions WHERE id=?", (sid,))[0]
        rows = self.db(
            "SELECT * FROM events WHERE session_id=? AND version=? AND ts<=?"
            " ORDER BY ts DESC, idx DESC LIMIT 1",
            (sid, s["v"], ts),
        )
        return rows[0] if rows else None

    # ---- 场景 ----
    def test_stall_periods_and_moment_query(self):
        r = self.post_analyze(scenario_stall())
        self.assertEqual(r.status_code, 302, r.data[:200])
        ps = self.periods()
        self.assertEqual(len(ps), 2)
        # 第一段：t=6ms 用尽（第4个数据段），t=20ms ACK 打开窗口
        self.assertEqual(ps[0]["start_ts"], ms(6))
        self.assertEqual(ps[0]["end_ts"], ms(20))
        self.assertEqual(ps[0]["min_margin"], 0)
        # 第二段：t=31ms 用尽，t=40ms 全部确认
        self.assertEqual(ps[1]["start_ts"], ms(31))
        self.assertEqual(ps[1]["end_ts"], ms(40))

        # t=15ms：窗口满，余量 0，在途 4000（重传不重复计）
        ev = self.event_at(ms(15))
        self.assertEqual((ev["margin"], ev["inflight"]), (0, 4000))
        # t=22ms：ACK 后余量 2000，在途 2000
        ev = self.event_at(ms(22))
        self.assertEqual((ev["margin"], ev["inflight"]), (2000, 2000))
        # t=26ms：过时 ACK 被忽略，状态不变
        ev = self.event_at(ms(26))
        self.assertEqual((ev["margin"], ev["inflight"]), (2000, 2000))
        # t=50ms：全部确认，余量=整个窗口 4000，在途 0
        ev = self.event_at(ms(50))
        self.assertEqual((ev["margin"], ev["inflight"]), (4000, 0))

        # HTTP 查询页面
        r = self.client.get(f"/session/1?at={BASE_S + 0.015}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("窗口用尽".encode(), r.data)
        r = self.client.get(f"/session/1?at={BASE_S + 0.050}")
        self.assertIn("有余量".encode(), r.data)

    def test_wraparound(self):
        isn = 0xFFFFFFA0  # 数据跨越 2^32 回绕
        f = handshake_frames(wscale_c=None, wscale_s=None, wnd_s=500, c_isn=isn)
        f.append((ms(3), c2s(1, S_ISN + 1, ACK | PSH, payload_len=500, isn=isn)))
        f.append((ms(10), s2c(1, (isn + 501) % (1 << 32), ACK, 500)))
        r = self.post_analyze(f)
        self.assertEqual(r.status_code, 302)
        ps = self.periods()
        self.assertEqual(len(ps), 1)
        self.assertEqual((ps[0]["start_ts"], ps[0]["end_ts"]), (ms(3), ms(10)))
        ev = self.event_at(ms(20))
        self.assertEqual((ev["margin"], ev["inflight"]), (500, 0))
        self.assertEqual(ev["cum_ack"], 501)

    def test_no_handshake_rejected(self):
        frames = [(ms(3), c2s(1, S_ISN + 1, ACK | PSH, payload_len=100))]
        r = self.post_analyze(frames)
        self.assertEqual(r.status_code, 302)
        s = self.db("SELECT * FROM sessions WHERE id=1")[0]
        self.assertEqual(s["status"], "failed")
        self.assertIn("握手", s["error"])

    def test_bidirectional_rejected(self):
        f = handshake_frames()
        f.append((ms(3), c2s(1, S_ISN + 1, ACK | PSH, payload_len=100)))
        f.append((ms(4), s2c(1, C_ISN + 101, ACK, 1000, payload_len=50)))  # 反向数据
        self.post_analyze(f)
        s = self.db("SELECT * FROM sessions WHERE id=1")[0]
        self.assertEqual(s["status"], "failed")
        self.assertIn("单向", s["error"])

    def test_span_limit_rejected(self):
        f = handshake_frames()
        f.append((ms(3), c2s(1, S_ISN + 1, ACK | PSH, payload_len=100)))
        f.append((ms(4), c2s(1 << 31, S_ISN + 1, ACK | PSH, payload_len=100)))
        self.post_analyze(f)
        s = self.db("SELECT * FROM sessions WHERE id=1")[0]
        self.assertEqual(s["status"], "failed")
        self.assertIn("2 GiB", s["error"])

    def test_supplement_corrects_and_conflict_rejected(self):
        # 初始：缺中间的 ACK，用尽持续到 t=60ms
        f = handshake_frames()
        for i in range(4):
            f.append((ms(3 + i), c2s(1 + i * 1000, S_ISN + 1, ACK | PSH, payload_len=1000)))
        f.append((ms(60), s2c(1, C_ISN + 4001, ACK, 1000)))
        self.post_analyze(f)
        ps = self.periods()
        self.assertEqual(len(ps), 1)
        self.assertEqual((ps[0]["start_ts"], ps[0]["end_ts"]), (ms(6), ms(60)))

        # 补传：t=20ms 的 ACK + t=21ms 新数据 + t=40ms 的 ACK（时间戳沿用原抓包）
        frag = [
            (ms(20), s2c(2001, C_ISN + 2001, ACK, 1000)),
            (ms(21), c2s(4001, S_ISN + 1, ACK | PSH, payload_len=1000)),
            (ms(21) + 500_000, c2s(5001, S_ISN + 1, ACK | PSH, payload_len=1000)),
            (ms(40), s2c(4001, C_ISN + 6001, ACK, 1000)),
        ]
        r = self.post_supplement(1, frag)
        self.assertEqual(r.status_code, 302)
        ps = self.periods()
        self.assertEqual(len(ps), 2)
        self.assertEqual((ps[0]["start_ts"], ps[0]["end_ts"]), (ms(6), ms(20)))
        self.assertEqual((ps[1]["start_ts"], ps[1]["end_ts"]), (ms(21) + 500_000, ms(40)))
        # t=60ms 的 ACK 变为过时 ACK，不影响最终状态
        ev = self.event_at(ms(70))
        self.assertEqual((ev["margin"], ev["inflight"]), (4000, 0))
        ver = self.db("SELECT current_version v FROM sessions WHERE id=1")[0]["v"]

        # 重复补传同一片段：全部去重，无新帧
        self.post_supplement(1, frag)
        stats = self.db("SELECT * FROM uploads ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual((stats["frames_added"], stats["frames_dup"]), (0, 4))
        self.assertEqual(
            self.db("SELECT current_version v FROM sessions WHERE id=1")[0]["v"], ver)

        # 冲突补传：同一时间戳、不同内容 → 整份拒绝，原诊断不变
        bad = [
            (ms(20), s2c(2001, C_ISN + 2001, ACK, 999)),  # 同 ts 不同帧
            (ms(22), c2s(4001, S_ISN + 1, ACK | PSH, payload_len=1000)),
        ]
        self.post_supplement(1, bad, name="bad.pcap")
        stats = self.db("SELECT * FROM uploads ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(stats["status"], "rejected")
        self.assertEqual(
            self.db("SELECT current_version v FROM sessions WHERE id=1")[0]["v"], ver)
        ps = self.periods()
        self.assertEqual(len(ps), 2)  # 诊断保持补传前结果
        n_frames = self.db("SELECT COUNT(*) c FROM frames WHERE session_id=1")[0]["c"]
        self.assertEqual(n_frames, 8 + 4)  # 初始8帧+补4帧，冲突帧未入库

    def test_supplement_earlier_frames_recompute(self):
        # 初始捕获从 t=10ms 之后开始（握手仍在），补入更早的数据帧
        f = handshake_frames(wnd_s=1000)
        f.append((ms(10), s2c(1, C_ISN + 2001, ACK, 1000)))  # ACK 前 2000B 的帧缺失
        self.post_analyze(f)
        ev = self.event_at(ms(11))
        self.assertEqual(ev["inflight"], 0)  # 缺失的数据帧尚未入库

        frag = [
            (ms(3), c2s(1, S_ISN + 1, ACK | PSH, payload_len=1000)),
            (ms(4), c2s(1001, S_ISN + 1, ACK | PSH, payload_len=1000)),
        ]
        self.post_supplement(1, frag)
        ev = self.event_at(ms(11))
        self.assertEqual(ev["inflight"], 0)   # t=10ms 已全部确认
        ev = self.event_at(ms(5))
        self.assertEqual(ev["inflight"], 2000)  # 补入后可见当时在途 2000

    def test_index_and_session_pages(self):
        self.post_analyze(scenario_stall())
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(C_IP.encode(), r.data)
        r = self.client.get("/session/1")
        self.assertEqual(r.status_code, 200)
        self.assertIn("窗口用尽时段".encode(), r.data)
        self.assertIn("分界帧".encode(), r.data)


if __name__ == "__main__":
    unittest.main()
