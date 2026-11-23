"""接收窗口排障工具 —— Flask 应用。

大文件上传卡住时，用发送端抓包（经典 PCAP，以太网）+ 上传方向四元组，
诊断接收窗口（通告窗口）何时用尽。
"""
import hashlib
import ipaddress
import os
import re
import threading
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

import db as dbmod
from analysis import AnalyzeError, analyze
from fragment import FragmentError, fragment_hash, group_key, reassemble
from pcaputil import PcapError, parse_fragment, parse_frame, parse_pcap

# 上传/重算串行化（读操作不加锁，SQLite WAL 下读写并发）
INGEST_LOCK = threading.Lock()

FLAG_NAMES = ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"))


class ConflictError(Exception):
    """补传片段与已有帧在同一时间戳上内容不同。"""


# ---------------------------------------------------------------- 时间工具

def fmt_ts(ns):
    if ns is None:
        return "—"
    sec, frac = divmod(int(ns), 1_000_000_000)
    dt = datetime.fromtimestamp(sec, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S") + f".{frac:09d} UTC"


def fmt_dur(ns):
    if ns is None:
        return "—"
    ns = int(ns)
    if ns < 1_000:
        return f"{ns} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.3f} µs"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.3f} ms"
    return f"{ns / 1_000_000_000:.3f} s"


_TS_RE = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?\s*$"
)


def parse_time(text):
    """接受 'YYYY-MM-DD HH:MM:SS[.fffffffff]'（UTC）或 epoch 秒（可含小数），返回纳秒。"""
    text = (text or "").strip()
    if not text:
        raise ValueError("时间为空")
    m = _TS_RE.match(text)
    if m:
        date, hh, mm, ss, frac = m.groups()
        dt = datetime.strptime(date, "%Y-%m-%d").replace(
            hour=int(hh), minute=int(mm), second=int(ss), tzinfo=timezone.utc
        )
        ns = int(dt.timestamp()) * 1_000_000_000
        if frac:
            ns += int(frac.ljust(9, "0"))
        return ns
    try:
        return int(Decimal(text) * Decimal(1_000_000_000))
    except (InvalidOperation, ValueError):
        raise ValueError(f"无法解析时间：{text!r}（支持 UTC 时间或 epoch 秒）")


def fmt_flags(flags):
    names = [n for bit, n in FLAG_NAMES if flags & bit]
    return ",".join(names) if names else "-"


# ---------------------------------------------------------------- 应用工厂

def create_app(config=None):
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "pcap-diag-dev-key")
    app.config["DB_PATH"] = os.environ.get("DB_PATH", "pcapdiag.db")
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GiB
    if config:
        app.config.update(config)

    dbmod.init_db(app.config["DB_PATH"])
    app.teardown_appcontext(dbmod.close_db)

    app.jinja_env.filters["fmt_ts"] = fmt_ts
    app.jinja_env.filters["fmt_dur"] = fmt_dur
    app.jinja_env.filters["fmt_flags"] = fmt_flags

    # ------------------------------------------------------------ 工具

    def parse_tuple_form(form):
        try:
            client_ip = str(ipaddress.IPv4Address(form.get("client_ip", "").strip()))
            server_ip = str(ipaddress.IPv4Address(form.get("server_ip", "").strip()))
        except ipaddress.AddressValueError as e:
            raise ValueError(f"IPv4 地址无效：{e}")
        try:
            client_port = int(form.get("client_port", ""))
            server_port = int(form.get("server_port", ""))
        except ValueError:
            raise ValueError("端口必须是数字")
        for p in (client_port, server_port):
            if not (1 <= p <= 65535):
                raise ValueError("端口必须在 1-65535 之间")
        return client_ip, client_port, server_ip, server_port

    def extract_conn_frames(data, client_ip, client_port, server_ip, server_port):
        """解析整个 PCAP，筛出属于该四元组的帧与上传方向的分片。

        返回 (frames_total, conn_frames, conn_fragments)。

        conn_frames 元素：(ts, hash, direction, parsed_dict, capture_no)。
        conn_fragments 元素：(ts, fragment_dict)。

        分片报文没有端口信息（非首片）或仅凭 IP 仍可判断方向，故只按
        「客户端 IP → 服务器 IP」收录上传方向的分片；是否真正属于该连接
        由首片中完整的 TCP 头在重组时确认。反向分片直接忽略。
        """
        frames_total = 0
        conn = []
        frags = []
        for ts, raw in parse_pcap(data):
            frames_total += 1
            pf = parse_frame(raw)
            if pf is not None:
                fwd = (
                    pf["src_ip"] == client_ip
                    and pf["src_port"] == client_port
                    and pf["dst_ip"] == server_ip
                    and pf["dst_port"] == server_port
                )
                rev = (
                    pf["src_ip"] == server_ip
                    and pf["src_port"] == server_port
                    and pf["dst_ip"] == client_ip
                    and pf["dst_port"] == client_port
                )
                if not (fwd or rev):
                    continue
                h = hashlib.blake2b(raw, digest_size=16).hexdigest()
                conn.append((ts, h, "fwd" if fwd else "rev", pf, frames_total))
                continue
            fr = parse_fragment(raw)
            if fr is None:
                continue
            if fr["src_ip"] != client_ip or fr["dst_ip"] != server_ip:
                continue  # 只处理上传方向的分片；反向/无关分片忽略
            fr["capture_no"] = frames_total
            frags.append((ts, fr))
        return frames_total, conn, frags

    def _session_meta(db, session_id):
        return db.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()

    def rebuild_fragment_frames(db, session_id):
        """由库中全部分片重算重组段，替换旧的派生帧。

        分片可多批到达、副本可分次补入；每次重建都从已入库的分片出发，
        因此补入更早副本让报文提前凑齐时，派生段的时间随之纠正，
        无需重读旧 PCAP。调用方须已持有写事务。
        """
        sess = _session_meta(db, session_id)
        rows = db.execute(
            "SELECT * FROM fragments WHERE session_id=?"
            " ORDER BY src_ip, dst_ip, ip_id, id",
            (session_id,),
        ).fetchall()

        groups = []
        cur_key = None
        for r in rows:
            k = group_key(r["src_ip"], r["dst_ip"], r["ip_id"])
            if k != cur_key:
                groups.append((k, []))
                cur_key = k
            groups[-1][1].append(r)

        derived = []
        for key, group_rows in groups:
            res = reassemble(
                group_rows, sess["client_port"], sess["server_port"], key
            )
            if res["frame"] is not None:  # FragmentError 向上抛
                derived.append(res["frame"])

        db.execute(
            "DELETE FROM frames WHERE session_id=? AND frag_key IS NOT NULL",
            (session_id,),
        )
        for f in derived:
            db.execute(
                "INSERT INTO frames (session_id,ts,hash,direction,flags,seq,ack,wnd,"
                "payload_len,wscale_opt,capture_no,upload_id,frag_key,frag_ref)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id,
                    f["ts"],
                    f["hash"],
                    f["direction"],
                    f["flags"],
                    f["seq"],
                    f["ack"],
                    f["wnd"],
                    f["payload_len"],
                    f["wscale_opt"],
                    f["capture_no"],
                    f["upload_id"],
                    f["frag_key"],
                    f["frag_ref"],
                ),
            )
        return len(derived)

    def store_analysis(db, session_id):
        """从库中全部帧重算诊断，事务内原子切换到新版本。

        调用方须已持有写事务；失败时抛异常，由调用方回滚，
        旧版本诊断因此保持可查。
        """
        rebuild_fragment_frames(db, session_id)
        rows = db.execute(
            "SELECT * FROM frames WHERE session_id=? ORDER BY ts, id", (session_id,)
        ).fetchall()
        result = analyze(rows)  # AnalyzeError 向上抛

        sess = db.execute(
            "SELECT current_version FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        version = sess["current_version"] + 1

        db.executemany(
            "INSERT INTO events (session_id,version,idx,ts,frame_id,frag_ref,cum_ack,"
            "data_end,right_edge,margin,inflight)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    session_id,
                    version,
                    i,
                    ev["ts"],
                    ev["frame_id"],
                    ev["frag_ref"],
                    ev["cum_ack"],
                    ev["data_end"],
                    ev["right_edge"],
                    ev["margin"],
                    ev["inflight"],
                )
                for i, ev in enumerate(result["events"])
            ],
        )
        db.executemany(
            "INSERT INTO periods (session_id,version,idx,start_ts,end_ts,start_frame,"
            "end_frame,start_frag_ref,end_frag_ref,min_margin)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    session_id,
                    version,
                    i,
                    p["start_ts"],
                    p["end_ts"],
                    p["start_frame"],
                    p["end_frame"],
                    p["start_frag_ref"],
                    p["end_frag_ref"],
                    p["min_margin"],
                )
                for i, p in enumerate(result["periods"])
            ],
        )
        meta, summary = result["meta"], result["summary"]
        db.execute(
            "UPDATE sessions SET status='ok', error=NULL, client_isn=?, server_isn=?,"
            " client_wscale=?, server_wscale=?, scaling=?, current_version=?,"
            " conn_frames=?, first_ts=?, last_ts=?, total_data_bytes=?, max_inflight=?,"
            " min_margin=?, exhausted_periods=?, exhausted_ns=? WHERE id=?",
            (
                meta["client_isn"],
                meta["server_isn"],
                meta["client_wscale"],
                meta["server_wscale"],
                1 if meta["scaling"] else 0,
                version,
                summary["conn_frames"],
                summary["first_ts"],
                summary["last_ts"],
                summary["total_data_bytes"],
                summary["max_inflight"],
                summary["min_margin"],
                summary["exhausted_periods"],
                summary["exhausted_ns"],
                session_id,
            ),
        )
        # 旧版本结果在新版本就绪后才删除（同一事务，读方看到的是原子切换）
        db.execute(
            "DELETE FROM events WHERE session_id=? AND version<>?", (session_id, version)
        )
        db.execute(
            "DELETE FROM periods WHERE session_id=? AND version<>?", (session_id, version)
        )
        return version, summary

    def insert_frames(db, session_id, upload_id, conn_frames):
        """初始导入：同一时间戳的同一帧只计一次（静默去重）。"""
        added = dup = 0
        for ts, h, direction, pf, capture_no in conn_frames:
            cur = db.execute(
                "INSERT OR IGNORE INTO frames (session_id,ts,hash,direction,flags,seq,ack,"
                "wnd,payload_len,wscale_opt,capture_no,upload_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id,
                    ts,
                    h,
                    direction,
                    pf["flags"],
                    pf["seq"],
                    pf["ack"],
                    pf["wnd"],
                    pf["payload_len"],
                    pf["wscale_opt"],
                    capture_no,
                    upload_id,
                ),
            )
            if cur.rowcount:
                added += 1
            else:
                dup += 1
        return added, dup

    def merge_supplement_frames(db, session_id, conn_frames):
        """补传合并：同时间戳同帧去重；同时间戳不同帧 -> ConflictError。"""
        to_add = []
        dup = 0
        seen = {}
        for ts, h, direction, pf, capture_no in conn_frames:
            prev = seen.get(ts)
            if prev is not None:
                if prev != h:
                    raise ConflictError(
                        f"补传文件内部在时间戳 {fmt_ts(ts)} 上存在两帧内容不同的报文"
                    )
                dup += 1
                continue
            seen[ts] = h
            rows = db.execute(
                "SELECT hash FROM frames WHERE session_id=? AND ts=?", (session_id, ts)
            ).fetchall()
            if rows:
                if h in {r["hash"] for r in rows}:
                    dup += 1  # 同一帧：只计一次
                    continue
                raise ConflictError(
                    f"时间戳 {fmt_ts(ts)} 上已存在内容不同的帧，整份补传被拒绝"
                )
            to_add.append((ts, h, direction, pf, capture_no))
        return to_add, dup

    def insert_fragments(db, session_id, upload_id, conn_frags):
        """入库上传方向的分片；同一副本（时间戳+内容）只计一次。

        非首片先到也保留：归属由之后到达的首片确认。
        """
        added = dup = 0
        for ts, fr in conn_frags:
            data = fr["data"]
            h = fragment_hash(
                data, fr["offset"], fr["ip_id"], fr["src_ip"], fr["dst_ip"]
            )
            cur = db.execute(
                "INSERT OR IGNORE INTO fragments (session_id,ts,hash,src_ip,dst_ip,"
                "ip_id,offset,mf,frag_len,data,capture_no,upload_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id,
                    ts,
                    h,
                    fr["src_ip"],
                    fr["dst_ip"],
                    fr["ip_id"],
                    fr["offset"],
                    fr["mf"],
                    fr["frag_len"],
                    data,
                    fr["capture_no"],
                    upload_id,
                ),
            )
            if cur.rowcount:
                added += 1
            else:
                dup += 1
        return added, dup

    def record_upload(db, session_id, kind, filename, stats, status, error=None):
        db.execute(
            "INSERT INTO uploads (session_id,kind,filename,uploaded_at,frames_total,"
            "frames_conn,frames_added,frames_dup,fragments_conn,fragments_added,"
            "fragments_dup,status,error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                session_id,
                kind,
                filename,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                stats.get("total", 0),
                stats.get("conn", 0),
                stats.get("added", 0),
                stats.get("dup", 0),
                stats.get("frag_conn", 0),
                stats.get("frag_added", 0),
                stats.get("frag_dup", 0),
                status,
                error,
            ),
        )

    # ------------------------------------------------------------ 路由

    @app.route("/")
    def index():
        sessions = dbmod.get_db().execute(
            "SELECT * FROM sessions ORDER BY id DESC"
        ).fetchall()
        return render_template("index.html", sessions=sessions)

    @app.route("/analyze", methods=["POST"])
    def analyze_upload():
        try:
            client_ip, client_port, server_ip, server_port = parse_tuple_form(
                request.form
            )
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("index"))
        upload = request.files.get("pcap")
        if not upload or not upload.filename:
            flash("请选择要上传的 PCAP 文件", "error")
            return redirect(url_for("index"))
        data = upload.read()
        if not data:
            flash("上传的文件为空", "error")
            return redirect(url_for("index"))
        try:
            frames_total, conn, frags = extract_conn_frames(
                data, client_ip, client_port, server_ip, server_port
            )
        except PcapError as e:
            flash(f"PCAP 解析失败：{e}", "error")
            return redirect(url_for("index"))
        if not conn and not frags:
            flash(
                "捕获中未找到该四元组的任何 TCP 报文，请确认填写的是上传方向的"
                " IPv4 四元组（客户端IP/端口 → 服务器IP/端口）",
                "error",
            )
            return redirect(url_for("index"))

        with INGEST_LOCK:
            db = dbmod.get_db()
            db.execute("BEGIN IMMEDIATE")
            try:
                cur = db.execute(
                    "INSERT INTO sessions (created_at,client_ip,client_port,server_ip,"
                    "server_port,status) VALUES (?,?,?,?,?,'pending')",
                    (
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        client_ip,
                        client_port,
                        server_ip,
                        server_port,
                    ),
                )
                session_id = cur.lastrowid
                cur = db.execute(
                    "INSERT INTO uploads (session_id,kind,filename,uploaded_at,"
                    "frames_total,frames_conn,status) VALUES (?,?,?,?,?,?,?)",
                    (
                        session_id,
                        "initial",
                        upload.filename,
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        frames_total,
                        len(conn),
                        "ok",
                    ),
                )
                upload_id = cur.lastrowid
                added, dup = insert_frames(db, session_id, upload_id, conn)
                frag_added, frag_dup = insert_fragments(
                    db, session_id, upload_id, frags
                )
                db.execute(
                    "UPDATE uploads SET frames_added=?, frames_dup=?,"
                    " fragments_conn=?, fragments_added=?, fragments_dup=?"
                    " WHERE id=?",
                    (added, dup, len(frags), frag_added, frag_dup, upload_id),
                )
                version, summary = store_analysis(db, session_id)
                db.execute("COMMIT")
            except (AnalyzeError, FragmentError) as e:
                db.execute("ROLLBACK")
                # 会话保留为失败状态，便于用户查看原因
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO sessions (created_at,client_ip,client_port,server_ip,"
                    "server_port,status,error) VALUES (?,?,?,?,?,'failed',?)",
                    (
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        client_ip,
                        client_port,
                        server_ip,
                        server_port,
                        str(e),
                    ),
                )
                db.execute("COMMIT")
                flash(f"该连接不满足分析条件：{e}", "error")
                return redirect(url_for("index"))
            except Exception:
                db.execute("ROLLBACK")
                raise
        flash(
            f"分析完成：连接帧 {summary['conn_frames']} 个，"
            f"窗口用尽时段 {summary['exhausted_periods']} 段",
            "ok",
        )
        return redirect(url_for("session", session_id=session_id))

    @app.route("/session/<int:session_id>")
    def session(session_id):
        db = dbmod.get_db()
        sess = db.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if sess is None:
            abort(404)

        periods, uploads, query = [], [], None
        if sess["status"] == "ok":
            periods = db.execute(
                "SELECT * FROM periods WHERE session_id=? AND version=? ORDER BY idx",
                (session_id, sess["current_version"]),
            ).fetchall()
            at = request.args.get("at", "").strip()
            if at:
                try:
                    ts = parse_time(at)
                    ev = db.execute(
                        "SELECT * FROM events WHERE session_id=? AND version=? AND ts<=?"
                        " ORDER BY ts DESC, idx DESC LIMIT 1",
                        (session_id, sess["current_version"], ts),
                    ).fetchone()
                    query = {"input": at, "ts": ts, "event": ev}
                except ValueError as e:
                    flash(str(e), "error")
                    query = {"input": at, "ts": None, "event": None}
        uploads = db.execute(
            "SELECT * FROM uploads WHERE session_id=? ORDER BY id DESC", (session_id,)
        ).fetchall()

        # 分界帧详情（重组段展示实际使其凑齐的分片）
        frame_ids, frag_ids = set(), set()
        for p in periods:
            frame_ids.add(p["start_frame"])
            if p["end_frame"] is not None:
                frame_ids.add(p["end_frame"])
            if p["start_frag_ref"] is not None:
                frag_ids.add(p["start_frag_ref"])
            if p["end_frag_ref"] is not None:
                frag_ids.add(p["end_frag_ref"])
        frames_map, frags_map = {}, {}
        if frame_ids:
            marks = ",".join("?" * len(frame_ids))
            for row in db.execute(
                f"SELECT * FROM frames WHERE id IN ({marks})", tuple(frame_ids)
            ):
                frames_map[row["id"]] = row
        if frag_ids:
            marks = ",".join("?" * len(frag_ids))
            for row in db.execute(
                f"SELECT * FROM fragments WHERE id IN ({marks})", tuple(frag_ids)
            ):
                frags_map[row["id"]] = row

        n_fragments = db.execute(
            "SELECT COUNT(*) c FROM fragments WHERE session_id=?", (session_id,)
        ).fetchone()["c"]
        n_frag_groups = db.execute(
            "SELECT COUNT(*) c FROM (SELECT 1 FROM fragments WHERE session_id=?"
            " GROUP BY src_ip,dst_ip,ip_id)",
            (session_id,),
        ).fetchone()["c"]

        return render_template(
            "session.html",
            s=sess,
            periods=periods,
            frames_map=frames_map,
            frags_map=frags_map,
            n_fragments=n_fragments,
            n_frag_groups=n_frag_groups,
            uploads=uploads,
            query=query,
        )

    @app.route("/session/<int:session_id>/supplement", methods=["POST"])
    def supplement(session_id):
        db = dbmod.get_db()
        sess = db.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if sess is None:
            abort(404)
        if sess["status"] != "ok":
            flash("该会话没有可沿用的诊断，无法补传", "error")
            return redirect(url_for("session", session_id=session_id))
        upload = request.files.get("pcap")
        if not upload or not upload.filename:
            flash("请选择要补传的 PCAP 片段", "error")
            return redirect(url_for("session", session_id=session_id))
        data = upload.read()
        try:
            frames_total, conn, frags = extract_conn_frames(
                data,
                sess["client_ip"],
                sess["client_port"],
                sess["server_ip"],
                sess["server_port"],
            )
        except PcapError as e:
            flash(f"补传片段解析失败：{e}（原诊断不受影响）", "error")
            return redirect(url_for("session", session_id=session_id))

        stats = {
            "total": frames_total,
            "conn": len(conn),
            "frag_conn": len(frags),
        }
        with INGEST_LOCK:
            try:
                # 冲突检查在写事务外完成：任何失败都不会触碰已有数据
                to_add, dup = merge_supplement_frames(db, session_id, conn)
                stats["added"], stats["dup"] = len(to_add), dup
                # 本次补传是否带来任何新分片副本（含首片到达改变归属的情形）
                frag_new = False
                for ts, fr in frags:
                    h = fragment_hash(
                        fr["data"], fr["offset"], fr["ip_id"],
                        fr["src_ip"], fr["dst_ip"],
                    )
                    if db.execute(
                        "SELECT 1 FROM fragments WHERE session_id=? AND ts=?"
                        " AND hash=? LIMIT 1",
                        (session_id, ts, h),
                    ).fetchone() is None:
                        frag_new = True
                        break
                if not to_add and not frag_new:
                    stats["frag_dup"] = len(frags)
                    record_upload(
                        db, session_id, "supplement", upload.filename, stats, "ok"
                    )
                    flash(
                        f"补传片段中的 {dup} 个连接帧与 "
                        f"{stats['frag_conn']} 个分片副本均已存在，诊断不变",
                        "ok",
                    )
                    return redirect(url_for("session", session_id=session_id))
                db.execute("BEGIN IMMEDIATE")
                try:
                    cur = db.execute(
                        "INSERT INTO uploads (session_id,kind,filename,uploaded_at,"
                        "frames_total,frames_conn,frames_added,frames_dup,"
                        "fragments_conn,status)"
                        " VALUES (?,?,?,?,?,?,?,?,?,'ok')",
                        (
                            session_id,
                            "supplement",
                            upload.filename,
                            datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            frames_total,
                            len(conn),
                            len(to_add),
                            dup,
                            len(frags),
                        ),
                    )
                    upload_id = cur.lastrowid
                    insert_frames(db, session_id, upload_id, to_add)
                    frag_added, frag_dup = insert_fragments(
                        db, session_id, upload_id, frags
                    )
                    stats["frag_added"], stats["frag_dup"] = frag_added, frag_dup
                    db.execute(
                        "UPDATE uploads SET fragments_added=?, fragments_dup=?"
                        " WHERE id=?",
                        (frag_added, frag_dup, upload_id),
                    )
                    # 补入较早帧/分片后，受影响诊断全部重算；失败则整体回滚
                    store_analysis(db, session_id)
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    raise
            except ConflictError as e:
                record_upload(
                    db, session_id, "supplement", upload.filename, stats, "rejected", str(e)
                )
                flash(f"补传被拒绝：{e}。原诊断保持不变。", "error")
                return redirect(url_for("session", session_id=session_id))
            except (AnalyzeError, FragmentError) as e:
                # 本次新增的帧/分片已随事务回滚；原诊断仍可查
                record_upload(
                    db, session_id, "supplement", upload.filename, stats, "failed", str(e)
                )
                flash(f"补传后连接不再满足分析条件：{e}。已回滚，原诊断仍可查询。", "error")
                return redirect(url_for("session", session_id=session_id))

        extra = ""
        if stats.get("frag_added") or stats.get("frag_dup"):
            extra = (
                f"，分片新增 {stats['frag_added']} 片、去重 {stats['frag_dup']} 片"
            )
        flash(
            f"补传完成：新增 {stats['added']} 帧{extra}，去重 {stats['dup']} 帧，诊断已更新",
            "ok",
        )
        return redirect(url_for("session", session_id=session_id))

    @app.errorhandler(413)
    def too_large(_e):
        flash("文件超过大小限制（1 GiB）", "error")
        return redirect(url_for("index"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, threaded=True)
