"""Back-office panel: access control, SQLi, mass assignment, command injection.

Checks that the admin panel authenticates and, per level, which of its flaws
remain: customer sessions reaching it, SQL injection on the login form and the
customer search, role elevation through mass assignment, command injection in
diagnostics, duty separation between admin roles, and traversal in the file
browser.
"""

import sys
from urllib.parse import quote

from harness import (ADMIN, CUSTOMER, csrf, execute, lab, login, parse_levels,
                     rows, run_module, text)

TITLE = "admin panel - access control, SQLi, mass assignment, RCE"

ADMIN_ROLES = {"admin": "NusaAdmin!2024", "cs123": "NusaCS!2024",
               "finance456": "NusaFinance!2024"}

EXPECT = {
    # a plain customer session must never reach the back office
    "customer_login":          (302, 302, 302, 302),
    "customer_reaches_admin":  (True, True, False, False),
    "customer_sees_flag":      (True, True, False, False),
    # customer credentials on the admin login, and the SQLi bypass
    # (sqli_login is still open on medium: V V P P in the feature matrix)
    "customer_creds_admin":    (302, 302, 401, 401),
    "sqli_admin_login":        (302, 302, 401, 401),
    "sqli_admin_bypass":       (True, True, False, False),
    # a real admin always gets in
    "admin_login":             (302, 302, 302, 302),
    "admin_dashboard":         (True, True, True, True),
    # SQLi on the customer search — still open on `hard`
    "search_sqli":             (True, True, True, False),
    # mass assignment elevates a customer to admin — still open on `hard`
    "mass_assignment":         (True, True, True, False),
    # command injection in the diagnostics form
    "command_injection":       (True, True, False, False),
    # duty separation between admin roles
    "cs_can_review_claims":    (True, True, True, False),
    # path traversal in the file browser
    "traversal_status":        (200, 200, 403, 403),
    "traversal_leaks":         (True, True, False, False),
    # reporting still works
    "csv_status":              (200, 200, 200, 200),
    "csv_mimetype":            ("text/csv",) * 4,
    # every admin page renders
    "pages_all_200":           (True, True, True, True),
}


def _admin_login(client, username, password):
    return client.post("/admin/login",
                       data={"username": username, "password": password,
                             "csrf_token": csrf(client, "/admin/login")},
                       follow_redirects=False)


def _is_admin_page(resp):
    return resp.status_code == 200 and "Navigasi administrator" in text(resp)


def _user_links(resp):
    return text(resp).count('href="/admin/users/')


def run(level):
    out = {}
    with lab(level) as (app, db_path, _uploads, tmpdir):
        # --- a customer session reaching the panel --------------------------
        customer = app.test_client()
        out["customer_login"] = login(customer).status_code
        panel = customer.get("/admin/")
        out["customer_reaches_admin"] = _is_admin_page(panel)
        out["customer_sees_flag"] = "FLAG{flag_in_admin_panel}" in text(panel)

        # --- credential abuse and SQLi on the admin login -------------------
        from app.security import _RATE
        _RATE.clear()
        out["customer_creds_admin"] = _admin_login(
            app.test_client(), *CUSTOMER).status_code

        _RATE.clear()
        sqli = app.test_client()
        out["sqli_admin_login"] = _admin_login(sqli, "admin' --", "apa-saja").status_code
        out["sqli_admin_bypass"] = "FLAG{flag_in_admin_panel}" in text(sqli.get("/admin/"))

        # --- a real admin ---------------------------------------------------
        _RATE.clear()
        client = app.test_client()
        out["admin_login"] = _admin_login(client, *ADMIN).status_code
        out["admin_dashboard"] = _is_admin_page(client.get("/admin/"))
        if not out["admin_dashboard"]:
            return out

        # --- SQLi on the customer search ------------------------------------
        payload = "' OR 1=1 OR '"      # survives the hard blacklist
        baseline = _user_links(client.get("/admin/users?q=zzzzz"))
        out["search_sqli"] = _user_links(
            client.get("/admin/users?q=" + quote(payload))) > baseline

        # --- mass assignment: role_id in the profile form --------------------
        target = rows(db_path, "SELECT id FROM users WHERE username='ani02'")[0]["id"]
        execute(db_path, "UPDATE users SET role_id = 1 WHERE id = ?", (target,))
        client.post(f"/admin/users/{target}",
                    data={"full_name": "Ani Wijaya", "role_id": "2",
                          "csrf_token": csrf(client, f"/admin/users/{target}")})
        out["mass_assignment"] = rows(
            db_path, "SELECT role_id FROM users WHERE id = ?", (target,))[0]["role_id"] == 2

        # --- command injection in diagnostics --------------------------------
        marker = "NUSABANK_INJECTED"
        body = text(client.post("/admin/diagnostics",
                                data={"host": f"127.0.0.1 | echo {marker}",
                                      "csrf_token": csrf(client, "/admin/diagnostics")}))
        import re
        block = re.search(r"Keluaran:</p>\s*<pre class=\"code-block\">(.*?)</pre>",
                          body, re.S)
        out["command_injection"] = bool(block) and marker in block.group(1)

        # --- duty separation: a CS admin approving claims --------------------
        execute(db_path, "UPDATE claims SET status = 'submitted' WHERE id = 1")
        cs = app.test_client()
        _RATE.clear()
        _admin_login(cs, "cs123", ADMIN_ROLES["cs123"])
        cs.post("/admin/claims/1/review",
                data={"decision": "approved", "csrf_token": csrf(cs, "/admin/kyc")})
        out["cs_can_review_claims"] = rows(
            db_path, "SELECT status FROM claims WHERE id = 1")[0]["status"] == "approved"

        # --- path traversal in the file browser ------------------------------
        import os
        secret = os.path.join(tmpdir, "traversal-secret.txt")
        with open(secret, "w", encoding="utf-8") as handle:
            handle.write("NUSABANK_TRAVERSAL_SECRET")
        resp = client.get("/admin/files?name=../traversal-secret.txt")
        out["traversal_status"] = resp.status_code
        out["traversal_leaks"] = b"NUSABANK_TRAVERSAL_SECRET" in resp.data

        # --- reporting --------------------------------------------------------
        export = client.get("/admin/reports/export?type=users")
        out["csv_status"] = export.status_code
        out["csv_mimetype"] = export.mimetype

        # --- every page renders -----------------------------------------------
        pages = ["/admin/users", "/admin/kyc", "/admin/claims", "/admin/transactions",
                 "/admin/tickets", "/admin/audit", "/admin/reports", "/admin/files",
                 "/admin/settings", "/admin/diagnostics", "/admin/users/4",
                 "/admin/tickets/1"]
        out["pages_all_200"] = all(
            client.get(page).status_code == 200 for page in pages)
    return out


if __name__ == "__main__":
    sys.exit(run_module(TITLE, run, EXPECT, parse_levels()))
