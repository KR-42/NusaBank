"""SQLite helpers. Connection is per-request and stored on flask.g."""

import sqlite3

from flask import current_app, g


def connect(path):
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, params=(), one=False):
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql, params=()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    last = cur.lastrowid
    cur.close()
    return last


def get_setting(key, default=None):
    try:
        row = query("SELECT value FROM settings WHERE key = ?", (key,), one=True)
        return row["value"] if row else default
    except sqlite3.Error:
        return default


def set_setting(key, value):
    execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
        (key, value),
    )


def log_audit(action, detail="", user_id=None, actor=None, ip=None, user_agent=None):
    from flask import request

    try:
        execute(
            "INSERT INTO audit_logs(user_id, actor, action, detail, ip, user_agent) "
            "VALUES(?,?,?,?,?,?)",
            (
                user_id,
                actor,
                action,
                detail,
                ip or (request.remote_addr if request else None),
                user_agent or (request.headers.get("User-Agent") if request else None),
            ),
        )
    except sqlite3.Error:
        pass


def init_app(app):
    app.teardown_appcontext(close_db)


def ensure_schema(app):
    """Create the schema when the database file does not exist yet.

    Seeding is handled separately by db/seed.py (and the Docker entrypoint).
    """
    import os

    path = app.config["DB_PATH"]
    if os.path.exists(path):
        return
    schema_path = os.path.join(app.config["BASE_DIR"], "db", "schema.sql")
    if not os.path.exists(schema_path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(open(schema_path, encoding="utf-8").read())
        conn.commit()
    finally:
        conn.close()