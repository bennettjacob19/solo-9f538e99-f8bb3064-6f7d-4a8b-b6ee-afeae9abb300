"""SQLite 存储层：会话、帧、分片、上传记录、按版本存放的诊断结果。"""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT NOT NULL,
    client_ip       TEXT NOT NULL,
    client_port     INTEGER NOT NULL,
    server_ip       TEXT NOT NULL,
    server_port     INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',  -- ok / failed
    error           TEXT,
    client_isn      INTEGER,
    server_isn      INTEGER,
    client_wscale   INTEGER,
    server_wscale   INTEGER,
    scaling         INTEGER,
    current_version INTEGER NOT NULL DEFAULT 0,
    conn_frames     INTEGER NOT NULL DEFAULT 0,
    first_ts        INTEGER,
    last_ts         INTEGER,
    total_data_bytes INTEGER,
    max_inflight    INTEGER,
    min_margin      INTEGER,
    exhausted_periods INTEGER,
    exhausted_ns    INTEGER
);

CREATE TABLE IF NOT EXISTS frames (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    ts          INTEGER NOT NULL,           -- UTC 纳秒
    hash        TEXT NOT NULL,              -- 原始帧（或重组段）内容摘要
    direction   TEXT NOT NULL,              -- fwd / rev
    flags       INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    ack         INTEGER NOT NULL,
    wnd         INTEGER NOT NULL,
    payload_len INTEGER NOT NULL,
    wscale_opt  INTEGER,
    capture_no  INTEGER NOT NULL,           -- 在其来源文件中的序号
    upload_id   INTEGER NOT NULL,
    frag_key    TEXT,                       -- 分片组键（重组段）；NULL = 普通帧
    frag_ref    INTEGER,                    -- 使重组段凑齐的分片（fragments.id）
    UNIQUE (session_id, ts, hash)
);
CREATE INDEX IF NOT EXISTS frames_session_ts ON frames(session_id, ts, id);

CREATE TABLE IF NOT EXISTS fragments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    ts          INTEGER NOT NULL,           -- 该副本的原抓包时间
    hash        TEXT NOT NULL,              -- 偏移 + 本片内容摘要
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    ip_id       INTEGER NOT NULL,
    offset      INTEGER NOT NULL,           -- IP 载荷字节偏移
    mf          INTEGER NOT NULL,           -- 更多分片标志
    frag_len    INTEGER NOT NULL,           -- 本片声明的 IP 载荷长度
    data        BLOB NOT NULL,              -- 实际抓到的本片字节
    capture_no  INTEGER NOT NULL,
    upload_id   INTEGER NOT NULL,
    UNIQUE (session_id, ts, hash)
);
CREATE INDEX IF NOT EXISTS fragments_group
    ON fragments(session_id, src_ip, dst_ip, ip_id, id);

CREATE TABLE IF NOT EXISTS uploads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id),
    kind        TEXT NOT NULL,              -- initial / supplement
    filename    TEXT,
    uploaded_at TEXT NOT NULL,
    frames_total   INTEGER NOT NULL DEFAULT 0,
    frames_conn    INTEGER NOT NULL DEFAULT 0,
    frames_added   INTEGER NOT NULL DEFAULT 0,
    frames_dup     INTEGER NOT NULL DEFAULT 0,
    fragments_conn  INTEGER NOT NULL DEFAULT 0,
    fragments_added INTEGER NOT NULL DEFAULT 0,
    fragments_dup   INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL,              -- ok / rejected / failed
    error       TEXT
);

CREATE TABLE IF NOT EXISTS events (
    session_id  INTEGER NOT NULL,
    version     INTEGER NOT NULL,
    idx         INTEGER NOT NULL,
    ts          INTEGER NOT NULL,
    frame_id    INTEGER NOT NULL,
    frag_ref    INTEGER,                    -- 重组段凑齐时的分片（fragments.id）
    cum_ack     INTEGER NOT NULL,
    data_end    INTEGER NOT NULL,
    right_edge  INTEGER NOT NULL,
    margin      INTEGER NOT NULL,
    inflight    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_lookup ON events(session_id, version, ts, idx);

CREATE TABLE IF NOT EXISTS periods (
    session_id  INTEGER NOT NULL,
    version     INTEGER NOT NULL,
    idx         INTEGER NOT NULL,
    start_ts    INTEGER NOT NULL,
    end_ts      INTEGER,                    -- NULL = 持续至捕获结束
    start_frame INTEGER NOT NULL,
    end_frame   INTEGER,
    start_frag_ref INTEGER,                 -- 起始分界帧为分片重组段时指向凑齐的分片
    end_frag_ref   INTEGER,
    min_margin  INTEGER NOT NULL
);
"""

# 旧库升级：CREATE TABLE IF NOT EXISTS 不会补列
_ADDED_COLUMNS = {
    "frames": (
        ("frag_key", "TEXT"),
        ("frag_ref", "INTEGER"),
    ),
    "events": (
        ("frag_ref", "INTEGER"),
    ),
    "periods": (
        ("start_frag_ref", "INTEGER"),
        ("end_frag_ref", "INTEGER"),
    ),
    "uploads": (
        ("fragments_conn", "INTEGER NOT NULL DEFAULT 0"),
        ("fragments_added", "INTEGER NOT NULL DEFAULT 0"),
        ("fragments_dup", "INTEGER NOT NULL DEFAULT 0"),
    ),
}


def _migrate(db):
    for table, cols in _ADDED_COLUMNS.items():
        have = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols:
            if name not in have:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS frames_frag_group"
        " ON frames(session_id, frag_key) WHERE frag_key IS NOT NULL"
    )


def get_db():
    if "db" not in g:
        db = sqlite3.connect(
            current_app.config["DB_PATH"], timeout=30, isolation_level=None
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=30000")
        g.db = db
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path):
    db = sqlite3.connect(db_path, isolation_level=None)
    try:
        db.executescript(SCHEMA)
        _migrate(db)
    finally:
        db.close()
