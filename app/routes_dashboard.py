"""Customer dashboard, profile and account overview."""

from flask import (Blueprint, abort, flash, g, redirect, render_template, request,
                   url_for)

from .db import execute, get_db, query
from .lab import current_policy
from .security import csrf_verify, hash_password, save_upload, valid_email, verify_password
from .utils import audit, login_required, rupiah

bp = Blueprint("dashboard", __name__)


def _accounts_for(user_id):
    return query(
        "SELECT * FROM accounts WHERE user_id = ? ORDER BY id",
        (user_id,),
        one=False,
    )


def _primary_account(user_id):
    row = query(
        "SELECT * FROM accounts WHERE user_id = ? ORDER BY id LIMIT 1",
        (user_id,),
        one=True,
    )
    return row


@bp.get("/dashboard")
@login_required
def index():
    user = g.user
    accounts = _accounts_for(user["id"])
    total = sum(a["balance"] or 0 for a in accounts)

    # VULN: idor_transactions — the mini statement is selected with a raw
    # parameter taken from the query string (?account_id=..) without checking
    # ownership. See routes_transactions for the full history page.
    account_id = request.args.get("account_id") or (accounts[0]["id"] if accounts else None)
    if account_id and not current_policy().is_vulnerable("idor_transactions"):
        # FIX: only accounts owned by the session user may be selected.
        owned = {str(a["id"]) for a in accounts}
        if str(account_id) not in owned:
            abort(403)
    recent = []
    if account_id:
        recent = query(
            "SELECT * FROM transactions WHERE account_id = ? "
            "ORDER BY created_at DESC, id DESC LIMIT 10",
            (account_id,),
        )

    cards = query("SELECT * FROM cards WHERE user_id = ?", (user["id"],))
    policies = query("SELECT * FROM insurance_policies WHERE user_id = ?",
                     (user["id"],))
    return render_template(
        "dashboard/index.html",
        accounts=accounts,
        total_balance=total,
        recent=recent,
        account_id=account_id,
        cards=cards,
        policies=policies,
        pending_kyc=user["kyc_status"] != "verified",
    )


@bp.get("/profile")
@login_required
def profile():
    user = g.user
    accounts = _accounts_for(user["id"])
    kyc_docs = query(
        "SELECT * FROM kyc_documents WHERE user_id = ? ORDER BY uploaded_at DESC",
        (user["id"],),
    )
    return render_template("dashboard/profile.html", accounts=accounts,
                           kyc_docs=kyc_docs)


@bp.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    user = g.user
    policy = current_policy()

    if request.method == "POST":
        csrf_verify()
        form = request.form
        full_name = (form.get("full_name") or "").strip()
        email = (form.get("email") or "").strip().lower()
        phone = (form.get("phone") or "").strip()
        address = (form.get("address") or "").strip()

        if not full_name or not valid_email(email):
            flash("Nama lengkap dan email yang valid wajib diisi.", "error")
            return render_template("dashboard/profile_edit.html", form=form), 400

        duplicate = query("SELECT 1 FROM users WHERE email = ? AND id != ?",
                          (email, user["id"]), one=True)
        if duplicate:
            flash("Email sudah dipakai akun lain.", "error")
            return render_template("dashboard/profile_edit.html", form=form), 400

        # VULN: mass_assignment — on easy/medium/hard every posted field whose
        # name matches a users column is written straight to the row, so
        # `role_id=2` or `kyc_status=verified` escalates the account.
        if policy.is_vulnerable("mass_assignment"):
            allowed = {c["name"] for c in
                       get_db().execute("PRAGMA table_info(users)").fetchall()}
            updates, values = [], []
            for field, value in form.items():
                if field in allowed and field not in ("password_hash", "id", "created_at"):
                    updates.append(f"{field} = ?")
                    values.append(value)
            if updates:
                values.append(user["id"])
                execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", values)
            audit("profile.update", f"fields={','.join(form.keys())}")
            flash("Profil diperbarui.", "success")
            return redirect(url_for("dashboard.profile"))

        # FIX: explicit column allowlist.
        execute(
            "UPDATE users SET full_name = ?, email = ?, phone = ?, address = ?, "
            "updated_at = datetime('now') WHERE id = ?",
            (full_name, email, phone, address, user["id"]),
        )
        audit("profile.update")
        flash("Profil diperbarui.", "success")
        return redirect(url_for("dashboard.profile"))

    return render_template("dashboard/profile_edit.html", form=user)


@bp.post("/profile/photo")
@login_required
def profile_photo():
    csrf_verify()
    file = request.files.get("photo")
    if not file or not file.filename:
        flash("Pilih berkas foto terlebih dahulu.", "error")
        return redirect(url_for("dashboard.profile"))
    try:
        stored, _original, _mime, _size = save_upload(file, subdir="photos")
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard.profile"))
    execute("UPDATE users SET photo = ? WHERE id = ?", (stored, g.user["id"]))
    audit("profile.photo", stored)
    flash("Foto profil diperbarui.", "success")
    return redirect(url_for("dashboard.profile"))


@bp.post("/profile/pin")
@login_required
def change_pin():
    csrf_verify()
    current = request.form.get("current_pin") or ""
    new_pin = request.form.get("new_pin") or ""
    confirm = request.form.get("confirm_pin") or ""

    policy = current_policy()
    if not verify_password(current, g.user["pin_hash"]):
        # VULN: pin_bypass — on easy the PIN check is skipped entirely.
        if not policy.is_vulnerable("pin_bypass"):
            flash("PIN saat ini salah.", "error")
            return redirect(url_for("dashboard.profile"))
    if not (len(new_pin) == 6 and new_pin.isdigit()):
        flash("PIN harus 6 digit angka.", "error")
        return redirect(url_for("dashboard.profile"))
    if new_pin != confirm:
        flash("Konfirmasi PIN tidak cocok.", "error")
        return redirect(url_for("dashboard.profile"))

    execute("UPDATE users SET pin_hash = ? WHERE id = ?",
            (hash_password(new_pin), g.user["id"]))
    audit("profile.change_pin")
    flash("PIN transaksi berhasil diperbarui.", "success")
    return redirect(url_for("dashboard.profile"))
