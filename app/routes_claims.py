"""Asuransi: polis nasabah, pengajuan klaim, unggah lampiran, status klaim."""

import os
import secrets

from flask import (Blueprint, abort, flash, g, redirect, render_template, request,
                   send_file, url_for)

from .db import execute, query
from .lab import current_policy
from .security import csrf_verify, safe_join_upload, save_upload
from .utils import audit, is_admin_user, login_required, rupiah

bp = Blueprint("claims", __name__)

CLAIM_CATEGORIES = ("jiwa", "kendaraan")


def _claim_no():
    while True:
        ref = f"CLM-{secrets.randbelow(900000) + 100000}"
        if not query("SELECT 1 FROM claims WHERE claim_no = ?", (ref,), one=True):
            return ref


def _owns(policy, row):
    """Ownership gate used by every claim view."""
    return (policy.is_vulnerable("idor_claims")
            or row["user_id"] == g.user["id"]
            or is_admin_user(g.user))


@bp.get("/insurance")
@login_required
def index():
    policies = query(
        "SELECT p.*, (SELECT COUNT(*) FROM claims c WHERE c.policy_id = p.id) "
        "AS claim_count FROM insurance_policies p WHERE p.user_id = ? "
        "ORDER BY p.id",
        (g.user["id"],),
    )
    claims = query(
        "SELECT c.*, p.policy_no, p.product FROM claims c "
        "JOIN insurance_policies p ON p.id = c.policy_id "
        "WHERE c.user_id = ? ORDER BY c.created_at DESC",
        (g.user["id"],),
    )
    return render_template("claims/index.html", policies=policies, claims=claims)


@bp.route("/insurance/claim", methods=["GET", "POST"])
@login_required
def claim_new():
    policy = current_policy()
    policies = query("SELECT * FROM insurance_policies WHERE user_id = ? ORDER BY id",
                     (g.user["id"],))

    if request.method == "POST":
        csrf_verify()
        policy_id = request.form.get("policy_id", type=int)
        description = (request.form.get("description") or "").strip()
        try:
            amount = int(request.form.get("amount") or 0)
        except ValueError:
            amount = 0

        insurance = query("SELECT * FROM insurance_policies WHERE id = ?",
                          (policy_id,), one=True)
        if not insurance:
            abort(404)

        # VULN: idor_claims — the policy id is not checked against the session
        # user, so a claim can be filed against someone else's policy.
        if not policy.is_vulnerable("idor_claims"):
            if insurance["user_id"] != g.user["id"]:
                abort(403)

        # VULN: claim_amount_bypass — the only cap is the client-side `max`
        # attribute. On easy/medium the server accepts negative amounts, zero
        # and values far above the policy coverage.
        if not policy.is_vulnerable("claim_amount_bypass"):
            if amount <= 0:
                flash("Nominal klaim harus lebih dari nol.", "error")
                return render_template("claims/claim_new.html", policies=policies), 400
            if amount > insurance["coverage"]:
                flash(f"Nominal klaim melebihi nilai pertanggungan "
                      f"({rupiah(insurance['coverage'])}).", "error")
                return render_template("claims/claim_new.html", policies=policies), 400

            if not policy.is_vulnerable("claim_cumulative_bypass"):
                # FIX: cap the total of all open/approved claims per policy.
                total = query(
                    "SELECT COALESCE(SUM(amount), 0) AS total FROM claims "
                    "WHERE policy_id = ? AND status IN ('submitted', 'approved')",
                    (insurance["id"],),
                    one=True,
                )["total"]
                if total + amount > insurance["coverage"]:
                    flash("Total klaim pada polis ini melebihi nilai "
                          "pertanggungan.", "error")
                    return render_template("claims/claim_new.html",
                                           policies=policies), 400
            else:
                # VULN: claim_cumulative_bypass (hard) — each claim is checked
                # against the coverage in isolation, so the same policy can be
                # drained with several claims that each pass on their own.
                pass
        # On every level the attachment is optional so the flow stays usable.

        attachment = None
        file = request.files.get("attachment")
        if file and file.filename:
            try:
                attachment, original, _mime, _size = save_upload(file, subdir="claims")
            except ValueError as exc:
                flash(str(exc), "error")
                return render_template("claims/claim_new.html", policies=policies), 400
            # Keep the original name around for the admin review screen.
            description = description or f"Lampiran: {original}"

        claim_no = _claim_no()
        execute(
            "INSERT INTO claims(claim_no, policy_id, user_id, amount, description, "
            "attachment, status) VALUES(?,?,?,?,?,?,?)",
            (claim_no, insurance["id"], insurance["user_id"], amount,
             description or "Pengajuan klaim asuransi", attachment, "submitted"),
        )
        audit("claim.create",
              f"claim={claim_no} policy={insurance['policy_no']} amount={amount}")
        flash(f"Klaim {claim_no} berhasil diajukan dan menunggu peninjauan.", "success")
        return redirect(url_for("claims.index"))

    return render_template("claims/claim_new.html", policies=policies)


@bp.get("/insurance/claim/<int:claim_id>")
@login_required
def claim_detail(claim_id):
    policy = current_policy()
    claim = query(
        "SELECT c.*, p.policy_no, p.product, p.coverage, u.full_name, u.username "
        "FROM claims c JOIN insurance_policies p ON p.id = c.policy_id "
        "JOIN users u ON u.id = c.user_id WHERE c.id = ?",
        (claim_id,),
        one=True,
    )
    if not claim:
        abort(404)

    # VULN: idor_claims — any authenticated user can read any claim by id,
    # including the admin note and the claimant's identity.
    # FIX: scope the lookup to the session user (or the back-office role).
    if not _owns(policy, claim):
        abort(403)

    return render_template("claims/claim_detail.html", claim=claim,
                           internal_note_visible=policy.is_vulnerable(
                               "internal_note_exposure"))


@bp.get("/insurance/claim/<int:claim_id>/attachment")
@login_required
def claim_attachment(claim_id):
    policy = current_policy()
    claim = query("SELECT * FROM claims WHERE id = ?", (claim_id,), one=True)
    if not claim or not claim["attachment"]:
        abort(404)
    if not _owns(policy, claim):
        abort(403)

    path = safe_join_upload(claim["attachment"])
    if not os.path.isfile(path):
        abort(404)
    audit("claim.attachment", f"claim_id={claim_id}")
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(claim["attachment"]))
