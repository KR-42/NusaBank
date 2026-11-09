"""Uploads: serve stored files and the KYC document flow.

Claims attachments live in routes_claims.py; profile photos are uploaded via
routes_dashboard.py. Both use the shared helpers in security.py.
"""

import os

from flask import (Blueprint, abort, current_app, g, redirect, render_template,
                   request, send_file, url_for)

from .db import execute, query
from .lab import current_policy
from .security import csrf_verify, safe_join_upload, save_upload
from .utils import audit, login_required

bp = Blueprint("uploads", __name__)

KYC_TYPES = ("ktp", "npwp", "selfie", "lainnya")


@bp.get("/uploads/<path:name>")
def raw_file(name):
    """Serve a stored upload.

    VULN: path_traversal — on easy/medium the name is joined to the upload
    root without canonicalisation, so ../db/nusabank.db (or legacy/flag.txt)
    is readable.
    FIX: safe_join_upload() canonicalises and rejects paths outside the root.
    """
    path = safe_join_upload(name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@bp.route("/kyc/upload", methods=["GET", "POST"])
@login_required
def kyc_upload():
    if request.method == "POST":
        csrf_verify()
        doc_type = request.form.get("doc_type") or "ktp"
        if doc_type not in KYC_TYPES:
            doc_type = "lainnya"
        file = request.files.get("document")
        if not file or not file.filename:
            abort(400, description="Berkas dokumen wajib diunggah.")
        try:
            stored, original, mime, size = save_upload(file, subdir="kyc")
        except ValueError as exc:
            abort(400, description=str(exc))

        execute(
            "INSERT INTO kyc_documents(user_id, doc_type, stored_name, original_name, "
            "mime_type, size_bytes, status, note) VALUES(?,?,?,?,?,?,?,?)",
            (g.user["id"], doc_type, stored, original, mime, size, "pending",
             "Menunggu peninjauan."),
        )
        if g.user["kyc_status"] != "verified":
            execute("UPDATE users SET kyc_status = 'pending' WHERE id = ?",
                    (g.user["id"],))
        audit("kyc.upload", f"type={doc_type} file={original}")
        return redirect(url_for("dashboard.profile"))

    return render_template("uploads/kyc_upload.html", doc_types=KYC_TYPES)


@bp.get("/kyc/download/<int:doc_id>")
@login_required
def kyc_download(doc_id):
    doc = query("SELECT * FROM kyc_documents WHERE id = ?", (doc_id,), one=True)
    if not doc:
        abort(404)

    # VULN: idor_kyc — on easy/medium/hard any logged-in user can download
    # any document by enumerating its id.
    # FIX: compare the document owner with the session user (admin exempt).
    if not current_policy().is_vulnerable("idor_kyc"):
        if doc["user_id"] != g.user["id"] and g.user.get("role") != "admin":
            abort(403)

    path = safe_join_upload(os.path.join("kyc", doc["stored_name"]))
    if not os.path.isfile(path):
        abort(404)
    audit("kyc.download", f"doc_id={doc_id}")
    return send_file(path, as_attachment=True, download_name=doc["original_name"])
