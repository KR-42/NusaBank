"""Authentication: login, register, logout, password reset, change password."""

import hashlib
import random
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, session, url_for)

from .db import execute, get_db, query
from .lab import current_policy
from .security import (create_reset_token, csrf_verify, hash_password,
                       issue_remember_cookie, login_is_locked,
                       password_policy_error, rate_limit_check,
                       register_login_failure, reset_login_failures,
                       rotate_session, valid_email, verify_password)
from .utils import audit, is_safe_redirect, login_required

bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _find_user_by_login(username):
    return query(
        "SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id = u.role_id "
        "WHERE u.username = ?",
        (username,),
        one=True,
    )


def _post_login_target(default):
    """Resolve the `next` parameter after a successful login."""
    target = request.args.get("next") or request.form.get("next")
    if not target:
        return default
    policy = current_policy()
    if policy.is_vulnerable("open_redirect"):
        # VULN: open_redirect — the raw `next` value is passed to redirect(),
        # so ?next=https://evil.example/phish sends users off-site.
        # On `hard` the check is a naive prefix test: //evil.example passes.
        if policy.is_hard and not target.startswith("/"):
            return default
        return target
    # FIX: only same-origin relative paths are accepted.
    return target if is_safe_redirect(target) else default


def _set_remember_cookie(response, user_id):
    raw, expiry = issue_remember_cookie(user_id)
    policy = current_policy()
    response.set_cookie(
        "nb_remember",
        raw,
        expires=expiry,
        httponly=not policy.is_vulnerable("insecure_cookies"),
        secure=not policy.is_vulnerable("insecure_cookies"),
        samesite=None if policy.is_vulnerable("insecure_cookies") else "Lax",
    )
    return response


def _new_account_number():
    while True:
        number = f"10{random.randint(10_000_000, 99_999_999)}"
        if not query("SELECT 1 FROM accounts WHERE account_number = ?", (number,), one=True):
            return number


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.get("user"):
        return redirect(url_for("dashboard.index"))

    next_url = request.args.get("next", "")
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        policy = current_policy()

        if not rate_limit_check(
            f"login:{username}" if policy.is_hard else f"login:{request.remote_addr}",
            limit=8, window_seconds=60,
        ):
            flash("Terlalu banyak percobaan login. Coba lagi sebentar.", "error")
            return render_template("auth/login.html", next_url=next_url), 429

        row = None
        if policy.is_vulnerable("sqli_login"):
            # VULN: sqli_login — username and password hash are concatenated
            # into the SQL string. Payload: username = admin' --
            digest = "md5:" + hashlib.md5(password.encode()).hexdigest()
            sql = (
                "SELECT u.*, r.name AS role FROM users u "
                "JOIN roles r ON r.id = u.role_id "
                f"WHERE u.username = '{username}' AND u.password_hash = '{digest}' "
                "AND u.is_active = 1"
            )
            try:
                row = get_db().execute(sql).fetchone()
            except sqlite3.Error as exc:
                current_app.logger.warning("login SQL error: %s", exc)
                row = None
        else:
            # FIX: parameterized query + constant-time hash verification.
            candidate = _find_user_by_login(username)
            if candidate and candidate["is_active"] and \
                    verify_password(password, candidate["password_hash"]):
                row = candidate

        execute(
            "INSERT INTO login_attempts(username, ip, success) VALUES(?,?,?)",
            (username, request.remote_addr, 1 if row else 0),
        )

        if not row:
            known = _find_user_by_login(username)
            if known:
                register_login_failure(known)
            if policy.is_vulnerable("user_enumeration"):
                # VULN: user_enumeration — distinct messages reveal which
                # usernames exist.
                message = ("Password salah." if known
                           else "Username tidak ditemukan.")
            else:
                message = "Username atau password salah."
            if known and login_is_locked(known):
                message = "Akun terkunci sementara karena terlalu banyak percobaan."
            flash(message, "error")
            return render_template("auth/login.html", next_url=next_url,
                                   username=username), 401

        if login_is_locked(row):
            flash("Akun terkunci sementara karena terlalu banyak percobaan.", "error")
            return render_template("auth/login.html", next_url=next_url), 423

        reset_login_failures(row)
        rotate_session(row["id"], remember=bool(request.form.get("remember")))
        audit("auth.login", f"username={row['username']}")

        response = redirect(_post_login_target(url_for("dashboard.index")))
        if request.form.get("remember"):
            response = _set_remember_cookie(response, row["id"])
        return response

    return render_template("auth/login.html", next_url=next_url)


@bp.get("/logout")
def logout():
    audit("auth.logout")
    session.clear()
    response = redirect(url_for("public.index"))
    response.delete_cookie("nb_remember")
    return response


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.get("user"):
        return redirect(url_for("dashboard.index"))

    policy = current_policy()
    if request.method == "POST":
        form = request.form
        username = (form.get("username") or "").strip()
        email = (form.get("email") or "").strip().lower()
        full_name = (form.get("full_name") or "").strip()
        phone = (form.get("phone") or "").strip()
        password = form.get("password") or ""
        confirm = form.get("confirm_password") or ""

        errors = []
        if not username or not email or not full_name:
            errors.append("Username, email, dan nama lengkap wajib diisi.")
        if not valid_email(email):
            errors.append("Format email tidak valid.")
        if password != confirm:
            errors.append("Konfirmasi password tidak cocok.")
        policy_error = password_policy_error(password, username, email)
        if policy_error:
            errors.append(policy_error)
        if query("SELECT 1 FROM users WHERE username = ?", (username,), one=True):
            # VULN: user_enumeration — registration confirms existing accounts.
            errors.append("Username sudah digunakan.")
        if query("SELECT 1 FROM users WHERE email = ?", (email,), one=True):
            errors.append("Email sudah terdaftar.")

        if errors:
            for message in errors:
                flash(message, "error")
            return render_template("auth/register.html", form=form), 400

        user_id = execute(
            "INSERT INTO users(username, email, password_hash, pin_hash, full_name, "
            "phone, address, role_id, kyc_status, is_active) "
            "VALUES(?,?,?,?,?,?,?,?,?,1)",
            (username, email, hash_password(password), hash_password("123456"),
             full_name, phone, "", 1, "pending"),
        )
        execute(
            "INSERT INTO accounts(user_id, account_number, account_type, label, balance) "
            "VALUES(?,?,?,?,0)",
            (user_id, _new_account_number(), "tabungan", "Rekening Utama"),
        )
        audit("auth.register", f"username={username}", user={"id": user_id,
                                                             "username": username})
        flash("Rekening berhasil dibuat. Silakan masuk untuk melanjutkan.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form={})


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------
@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    policy = current_policy()
    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        user = query(
            "SELECT * FROM users WHERE email = ? OR username = ?",
            (identifier.lower(), identifier),
            one=True,
        )
        if not user:
            if policy.is_vulnerable("user_enumeration"):
                flash("Email atau username tidak terdaftar.", "error")
            else:
                flash("Jika akun terdaftar, tautan reset telah dikirim.", "info")
            return render_template("auth/forgot.html"), 200

        token = create_reset_token(user)
        link = url_for("auth.reset_password", token=token, _external=True)
        if policy.is_vulnerable("predictable_reset_token"):
            # VULN: predictable_reset_token — the token is shown directly in
            # the page and is derived from the user id + date.
            flash(f"Tautan reset (mode lab): {link}", "info")
        else:
            # FIX: token is random and only delivered out-of-band. In this lab
            # "out-of-band" means the server console.
            current_app.logger.info("Password reset link for %s: %s", user["username"], link)
            flash("Jika akun terdaftar, tautan reset telah dikirim.", "info")
        return render_template("auth/forgot.html")

    return render_template("auth/forgot.html")


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    policy = current_policy()
    row = query("SELECT * FROM reset_tokens WHERE token = ?", (token,), one=True)
    if not row:
        flash("Token reset tidak valid.", "error")
        return redirect(url_for("auth.forgot_password"))

    expired = True
    try:
        expired = datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        pass
    if row["used"] or expired:
        flash("Token reset sudah kedaluwarsa atau telah digunakan.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        user = query("SELECT * FROM users WHERE id = ?", (row["user_id"],), one=True)
        error = password_policy_error(password, user["username"] if user else None,
                                      user["email"] if user else None)
        if error:
            flash(error, "error")
            return render_template("auth/reset.html", token=token), 400
        if password != confirm:
            flash("Konfirmasi password tidak cocok.", "error")
            return render_template("auth/reset.html", token=token), 400

        execute("UPDATE users SET password_hash = ?, updated_at = datetime('now') "
                "WHERE id = ?", (hash_password(password), row["user_id"]))
        execute("UPDATE reset_tokens SET used = 1 WHERE id = ?", (row["id"],))
        audit("auth.password_reset", f"user_id={row['user_id']}")
        flash("Password berhasil diubah. Silakan masuk dengan password baru.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset.html", token=token)


# ---------------------------------------------------------------------------
# Change password (authenticated)
# ---------------------------------------------------------------------------
@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        csrf_verify()
        current = request.form.get("current_password") or ""
        new = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""

        if not verify_password(current, g.user["password_hash"]):
            flash("Password saat ini salah.", "error")
            return render_template("auth/change_password.html"), 400
        if new != confirm:
            flash("Konfirmasi password baru tidak cocok.", "error")
            return render_template("auth/change_password.html"), 400
        error = password_policy_error(new, g.user["username"], g.user["email"])
        if error:
            flash(error, "error")
            return render_template("auth/change_password.html"), 400

        execute("UPDATE users SET password_hash = ?, updated_at = datetime('now') "
                "WHERE id = ?", (hash_password(new), g.user["id"]))
        audit("auth.change_password")
        flash("Password berhasil diperbarui.", "success")
        return redirect(url_for("dashboard.profile"))

    return render_template("auth/change_password.html")
