"""Back-office panel: /admin/* — statistik, nasabah, KYC, klaim, tiket,
transaksi, audit log, pengaturan, ekspor laporan, dan diagnostik jaringan.

Panel ini punya sesi sendiri (`session["admin_uid"]`) yang terpisah dari sesi
nasabah (`session["uid"]`), sehingga login nasabah dan login admin tidak saling
menimpa. Setiap view melewati decorator `admin_access()` yang memutuskan boleh
atau tidaknya akses berdasarkan LAB_LEVEL:

  easy/medium  -> `admin_no_role_check` aktif: sesi nasabah mana pun (atau
                  siapa pun yang lolos SQLi login admin) dianggap administrator.
  hard         -> wajib sesi admin + role berawalan `admin`, tetapi seluruh
                  role back-office boleh melakukan semua aksi (celah halus:
                  `admin_cs` bisa menyetujui klaim dan mengubah pengaturan).
  patched      -> sesi admin + role + matriks PERMISSIONS per aksi.
"""

import csv
import functools
import io
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timedelta

from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, send_file, session, url_for)

from .db import execute, get_db, get_setting, query, set_setting
from .lab import current_policy
from .security import (csrf_verify, rate_limit_check, safe_join_upload,
                       verify_password)
from .utils import audit, paginate, rupiah

bp = Blueprint("admin", __name__, url_prefix="/admin")

PAGE_SIZE = 20

KYC_STATUSES = ("pending", "verified", "rejected")
CLAIM_STATUSES = ("submitted", "approved", "rejected")
TICKET_STATUSES = ("open", "in_progress", "closed")
ROLE_NAMES = ("user", "admin", "admin_cs", "admin_finance")

# Kolom users yang aman diedit lewat formulir profil back-office.
EDITABLE_USER_COLUMNS = ("full_name", "email", "phone", "address",
                         "kyc_status", "is_active")

# Kunci settings yang boleh diubah operator (dipakai hanya ketika patched).
SAFE_SETTING_KEYS = ("site_name", "site_tagline", "support_email", "transfer_fee",
                     "deposit_rate", "loan_rate", "maintenance_mode",
                     "webhook_allowlist")

# ---------------------------------------------------------------------------
# Otorisasi back-office
# ---------------------------------------------------------------------------
# FIX: pemisahan tugas (segregation of duties) untuk level `patched`. Pada
# level lain matriks ini sengaja tidak dipakai.
PERMISSIONS = {
    "admin": {"*"},
    "admin_cs": {"dashboard.read", "users.read", "kyc.review", "tickets.manage",
                 "claims.read", "files.read"},
    "admin_finance": {"dashboard.read", "users.read", "claims.review",
                      "transactions.read", "reports.export", "audit.read",
                      "files.read"},
}


def _is_backoffice(row):
    """True when the row carries a back-office role (works for Row and dict)."""
    if not row:
        return False
    try:
        role = row["role"]
    except (KeyError, IndexError):
        return False
    return str(role or "").startswith("admin")


def _load_backoffice(uid):
    return query(
        "SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id = u.role_id "
        "WHERE u.id = ?",
        (uid,),
        one=True,
    )


def current_admin():
    """Resolve the back-office actor for this request (cached on flask.g)."""
    if "admin_user" in g:
        return g.admin_user

    g.admin_user = None
    policy = current_policy()

    uid = session.get("admin_uid")
    if uid is not None:
        row = _load_backoffice(uid)
        if row and row["is_active"] and _is_backoffice(row):
            g.admin_user = row
            return row
        session.pop("admin_uid", None)

    if policy.is_vulnerable("admin_no_role_check") and g.get("user"):
        # VULN: admin_no_role_check — pada easy/medium setiap sesi nasabah yang
        # valid otomatis menjadi administrator. Cukup login sebagai budi01 lalu
        # buka http://127.0.0.1:8080/admin
        g.admin_user = g.user
        return g.user

    return None


def admin_access(permission=None):
    """Gate every /admin view; `permission` is only enforced on `patched`."""

    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            admin = current_admin()
            if not admin:
                if not g.get("user") and not session.get("admin_uid"):
                    flash("Silakan masuk ke panel administrator.", "info")
                else:
                    flash("Akun ini tidak memiliki akses ke panel administrator.",
                          "error")
                return redirect(url_for("admin.login",
                                        next=request.full_path.rstrip("?")))

            policy = current_policy()
            if policy.level_is_patched and permission:
                # FIX: enforcement per aksi berdasarkan role.
                allowed = PERMISSIONS.get(admin["role"], set())
                if "*" not in allowed and permission not in allowed:
                    audit("admin.permission_denied", f"{permission} {request.path}")
                    abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def _render(template, **context):
    context.setdefault("admin_user", current_admin())
    return render_template(template, **context)


def _can(action):
    """True when the current actor may perform `action` (patched only)."""
    admin = current_admin()
    if not admin:
        return False
    if not current_policy().level_is_patched:
        return True
    allowed = PERMISSIONS.get(admin["role"], set())
    return "*" in allowed or action in allowed


# ---------------------------------------------------------------------------
# Login / logout — sesi terpisah dari sesi nasabah
# ---------------------------------------------------------------------------
@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_admin():
        return redirect(url_for("admin.dashboard"))

    next_url = request.args.get("next", "")
    policy = current_policy()

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not rate_limit_check(f"admin-login:{request.remote_addr}",
                                limit=10, window_seconds=60):
            flash("Terlalu banyak percobaan login admin.", "error")
            return _render("admin/login.html", next_url=next_url), 429

        row = None
        if policy.is_vulnerable("sqli_login"):
            # VULN: sqli_login — username dan digest password dikonkatenasi ke
            # string SQL pada login administrator juga.
            # Payload: username = admin' --
            import hashlib

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
                current_app.logger.warning("admin login SQL error: %s", exc)
                row = None
        else:
            # FIX: query berparameter + verifikasi hash constant-time.
            candidate = _load_backoffice_by_username(username)
            if candidate and candidate["is_active"] and \
                    verify_password(password, candidate["password_hash"]):
                row = candidate

        if row and (policy.is_vulnerable("admin_no_role_check")
                    or _is_backoffice(row)):
            # VULN: admin_no_role_check — pada easy/medium akun nasabah biasa
            # pun diterima di /admin/login.
            session["admin_uid"] = row["id"]
            audit("admin.login", f"username={row['username']} role={row['role']}")
            target = next_url or url_for("admin.dashboard")
            return redirect(target)

        if row:
            # Akun valid tetapi bukan back-office (hard/patched).
            flash("Akun ini bukan akun administrator.", "error")
        elif policy.is_vulnerable("user_enumeration"):
            known = _load_backoffice_by_username(username)
            flash("Password salah." if known else "Username admin tidak ditemukan.",
                  "error")
        else:
            flash("Username atau password salah.", "error")
        return _render("admin/login.html", next_url=next_url,
                       username=username), 401

    return _render("admin/login.html", next_url=next_url)


def _load_backoffice_by_username(username):
    return query(
        "SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id = u.role_id "
        "WHERE u.username = ?",
        (username,),
        one=True,
    )


@bp.get("/logout")
def logout():
    admin = current_admin()
    if admin:
        audit("admin.logout", f"username={admin['username']}")
    session.pop("admin_uid", None)
    g.admin_user = None
    flash("Anda telah keluar dari panel administrator.", "info")
    return redirect(url_for("public.index"))


# ---------------------------------------------------------------------------
# Dashboard statistik
# ---------------------------------------------------------------------------
@bp.get("/")
@admin_access("dashboard.read")
def dashboard():
    policy = current_policy()

    def scalar(sql, params=()):
        row = query(sql, params, one=True)
        return list(row)[0] if row else 0

    stats = {
        "users": scalar("SELECT COUNT(*) FROM users"),
        "customers": scalar("SELECT COUNT(*) FROM users u JOIN roles r "
                            "ON r.id = u.role_id WHERE r.name = 'user'"),
        "balance": scalar("SELECT COALESCE(SUM(balance), 0) FROM accounts"),
        "tx_today": scalar("SELECT COUNT(*) FROM transactions "
                           "WHERE date(created_at) = date('now')"),
        "kyc_pending": scalar("SELECT COUNT(*) FROM kyc_documents "
                              "WHERE status = 'pending'"),
        "claims_pending": scalar("SELECT COUNT(*) FROM claims "
                                 "WHERE status = 'submitted'"),
        "tickets_open": scalar("SELECT COUNT(*) FROM tickets "
                              "WHERE status != 'closed'"),
        "claims_amount": scalar("SELECT COALESCE(SUM(amount), 0) FROM claims "
                                "WHERE status = 'submitted'"),
    }

    recent = query(
        "SELECT t.*, a.account_number, u.full_name, u.username "
        "FROM transactions t JOIN accounts a ON a.id = t.account_id "
        "JOIN users u ON u.id = a.user_id "
        "ORDER BY t.created_at DESC, t.id DESC LIMIT 12"
    )
    pending_kyc = query(
        "SELECT k.*, u.full_name, u.username FROM kyc_documents k "
        "JOIN users u ON u.id = k.user_id WHERE k.status = 'pending' "
        "ORDER BY k.uploaded_at DESC LIMIT 6"
    )
    pending_claims = query(
        "SELECT c.*, u.full_name, u.username FROM claims c "
        "JOIN users u ON u.id = c.user_id WHERE c.status = 'submitted' "
        "ORDER BY c.created_at DESC LIMIT 6"
    )

    return _render(
        "admin/dashboard.html",
        stats=stats,
        recent=recent,
        pending_kyc=pending_kyc,
        pending_claims=pending_claims,
        # VULN: sensitive_robots + admin_no_role_check — flag panel admin
        # terbaca siapa pun yang berhasil masuk ke /admin.
        panel_flag=get_setting("flag_admin_panel", ""),
        weak_sessions=policy.is_vulnerable("admin_no_role_check"),
    )


# ---------------------------------------------------------------------------
# Manajemen nasabah
# ---------------------------------------------------------------------------
def _user_rows(q, status):
    """Daftar nasabah. SQLi hidup pada cabang konkatenasi."""
    policy = current_policy()
    sql = (
        "SELECT u.id, u.username, u.email, u.full_name, u.phone, u.kyc_status, "
        "u.is_active, u.created_at, r.name AS role, "
        "(SELECT COUNT(*) FROM accounts a WHERE a.user_id = u.id) AS account_count, "
        "(SELECT COALESCE(SUM(a.balance), 0) FROM accounts a WHERE a.user_id = u.id) "
        "AS total_balance FROM users u JOIN roles r ON r.id = u.role_id WHERE 1=1"
    )

    if policy.is_vulnerable("sqli_search"):
        if policy.is_hard:
            # VULN: sqli_search (hard) — parameterisasi diganti dengan blacklist
            # case-sensitive yang hanya menyaring UNION, komentar SQL, dan ';'.
            # Bypass tanpa kata terlarang:
            #   q=%' OR 1=1 AND u.full_name LIKE '
            for banned in ("UNION", "--", "/*", ";"):
                q = q.replace(banned, "")
            if q:
                sql += (f" AND (u.username LIKE '%{q}%' OR u.full_name LIKE '%{q}%' "
                        f"OR u.email LIKE '%{q}%')")
        else:
            # VULN: sqli_search — nilai pencarian dikonkatenasi langsung.
            # Payload: q=' OR '1'='1
            if q:
                sql += (f" AND (u.username LIKE '%{q}%' OR u.full_name LIKE '%{q}%' "
                        f"OR u.email LIKE '%{q}%')")
        if status in ("pending", "verified", "rejected"):
            sql += f" AND u.kyc_status = '{status}'"
        sql += " ORDER BY u.id"
        return get_db().execute(sql).fetchall()

    # FIX: seluruh nilai terikat sebagai parameter prepared statement.
    params = []
    if q:
        like = f"%{q}%"
        sql += (" AND (u.username LIKE ? OR u.full_name LIKE ? OR u.email LIKE ?)")
        params.extend([like, like, like])
    if status in KYC_STATUSES:
        sql += " AND u.kyc_status = ?"
        params.append(status)
    sql += " ORDER BY u.id"
    return get_db().execute(sql, params).fetchall()


@bp.get("/users")
@admin_access("users.read")
def users():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    page = request.args.get("page", 1, type=int)

    try:
        rows = _user_rows(q, status)
        error = None
    except sqlite3.Error as exc:
        # VULN: verbose_errors — pesan SQL mentah pada easy/medium.
        rows = []
        error = f"Query error: {exc}" if current_policy().is_vulnerable(
            "verbose_errors") else "Pencarian gagal diproses."

    page_data = paginate(rows, page, PAGE_SIZE)
    return _render("admin/users.html", rows=page_data["items"], page=page_data,
                   q=q, status=status, error=error, statuses=KYC_STATUSES)


@bp.route("/users/<int:user_id>", methods=["GET", "POST"])
@admin_access("users.read")
def user_detail(user_id):
    policy = current_policy()
    row = query(
        "SELECT u.*, r.name AS role FROM users u JOIN roles r ON r.id = u.role_id "
        "WHERE u.id = ?", (user_id,), one=True,
    )
    if not row:
        abort(404)

    if request.method == "POST":
        csrf_verify()
        if not _can("users.manage"):
            abort(403)

        if policy.is_vulnerable("mass_assignment"):
            all_columns = {r["name"] for r in query("PRAGMA table_info(users)")}
            if policy.is_hard:
                # VULN: mass_assignment (hard) — pembaru memfilter field yang
                # diposting terhadap whitelist, tetapi `role_id` salah ikut
                # dimasukkan sehingga satu request menaikkan hak akses.
                # Payload: role_id=2 (super-admin)
                allowed = set(EDITABLE_USER_COLUMNS) | {"role_id"}
            else:
                # VULN: mass_assignment — setiap key yang kebetulan cocok
                # dengan kolom tabel users ditulis apa adanya.
                # Payload: role_id=2&kyc_status=verified&is_active=1
                allowed = all_columns - {"id", "password_hash", "pin_hash",
                                         "created_at", "updated_at"}
            updates = {k: v for k, v in request.form.items() if k in allowed}
        else:
            # FIX: whitelist sempit; perubahan role lewat aksi terpisah.
            updates = {k: request.form.get(k) for k in EDITABLE_USER_COLUMNS
                       if request.form.get(k) is not None}

        if updates:
            sets = ", ".join(f'"{col}" = ?' for col in updates)
            execute(f"UPDATE users SET {sets}, updated_at = datetime('now') "
                    f"WHERE id = ?", list(updates.values()) + [user_id])
            audit("admin.user.update",
                  f"user_id={user_id} fields={','.join(sorted(updates))}")
            flash("Data nasabah diperbarui.", "success")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    accounts = query("SELECT * FROM accounts WHERE user_id = ? ORDER BY id", (user_id,))
    docs = query("SELECT * FROM kyc_documents WHERE user_id = ? "
                 "ORDER BY uploaded_at DESC", (user_id,))
    tickets = query("SELECT * FROM tickets WHERE user_id = ? "
                    "ORDER BY updated_at DESC LIMIT 8", (user_id,))
    claims = query("SELECT * FROM claims WHERE user_id = ? "
                   "ORDER BY created_at DESC LIMIT 8", (user_id,))
    roles = query("SELECT * FROM roles ORDER BY id")

    return _render("admin/user_detail.html", row=row, accounts=accounts, docs=docs,
                   tickets=tickets, claims=claims, roles=roles,
                   editable=EDITABLE_USER_COLUMNS, statuses=KYC_STATUSES,
                   can_manage=_can("users.manage"))


@bp.post("/users/<int:user_id>/toggle")
@admin_access("users.manage")
def user_toggle(user_id):
    csrf_verify()
    row = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if not row:
        abort(404)
    new_state = 0 if row["is_active"] else 1
    execute("UPDATE users SET is_active = ?, updated_at = datetime('now') "
            "WHERE id = ?", (new_state, user_id))
    audit("admin.user.toggle", f"user_id={user_id} active={new_state}")
    flash(f"Akun {row['username']} {'diaktifkan' if new_state else 'dinonaktifkan'}.",
          "success")
    return redirect(url_for("admin.user_detail", user_id=user_id))


@bp.post("/users/<int:user_id>/role")
@admin_access("users.manage")
def user_role(user_id):
    """Perubahan role eksplisit — hanya level patched yang benar-benar ketat."""
    csrf_verify()
    policy = current_policy()
    role_name = (request.form.get("role") or "").strip()
    if role_name not in ROLE_NAMES:
        abort(400)

    if not policy.level_is_patched:
        # VULN: mass_assignment — pada easy/medium/hard tidak ada pemeriksaan
        # tambahan; role apa pun dapat dipasang ke akun mana pun.
        pass
    elif current_admin()["role"] != "admin":
        # FIX: hanya super-admin yang boleh mengubah role.
        abort(403)

    role_id = query("SELECT id FROM roles WHERE name = ?", (role_name,), one=True)
    if not role_id:
        abort(400)
    execute("UPDATE users SET role_id = ?, updated_at = datetime('now') "
            "WHERE id = ?", (role_id["id"], user_id))
    audit("admin.user.role", f"user_id={user_id} role={role_name}")
    flash(f"Role diubah menjadi {role_name}.", "success")
    return redirect(url_for("admin.user_detail", user_id=user_id))


# ---------------------------------------------------------------------------
# Verifikasi KYC
# ---------------------------------------------------------------------------
@bp.get("/kyc")
@admin_access("kyc.review")
def kyc():
    status = (request.args.get("status") or "pending").strip()
    sql = ("SELECT k.*, u.full_name, u.username, u.kyc_status FROM kyc_documents k "
           "JOIN users u ON u.id = k.user_id")
    params = []
    if status in KYC_STATUSES:
        sql += " WHERE k.status = ?"
        params.append(status)
    sql += " ORDER BY k.uploaded_at DESC"
    rows = query(sql, params)
    return _render("admin/kyc.html", rows=rows, status=status, statuses=KYC_STATUSES)


@bp.get("/kyc/<int:doc_id>/file")
@admin_access("kyc.review")
def kyc_file(doc_id):
    doc = query("SELECT * FROM kyc_documents WHERE id = ?", (doc_id,), one=True)
    if not doc:
        abort(404)
    path = safe_join_upload(os.path.join("kyc", doc["stored_name"]))
    if not os.path.isfile(path):
        abort(404)
    audit("admin.kyc.file", f"doc_id={doc_id}")
    return send_file(path, as_attachment=True, download_name=doc["original_name"])


@bp.post("/kyc/<int:doc_id>/review")
@admin_access("kyc.review")
def kyc_review(doc_id):
    csrf_verify()
    doc = query("SELECT * FROM kyc_documents WHERE id = ?", (doc_id,), one=True)
    if not doc:
        abort(404)
    decision = (request.form.get("decision") or "").strip()
    note = (request.form.get("note") or "").strip()[:500]
    if decision not in ("verified", "rejected"):
        abort(400)

    execute("UPDATE kyc_documents SET status = ?, note = ?, reviewed_by = ?, "
            "reviewed_at = datetime('now') WHERE id = ?",
            (decision, note or None, current_admin()["id"], doc_id))
    execute("UPDATE users SET kyc_status = ?, updated_at = datetime('now') "
            "WHERE id = ?", (decision, doc["user_id"]))
    audit("admin.kyc.review", f"doc_id={doc_id} decision={decision}")
    flash(f"Dokumen KYC #{doc_id} ditandai {decision}.", "success")
    return redirect(url_for("admin.kyc", status=(request.form.get("status") or "pending")))


# ---------------------------------------------------------------------------
# Klaim asuransi
# ---------------------------------------------------------------------------
@bp.get("/claims")
@admin_access("claims.read")
def claims():
    status = (request.args.get("status") or "submitted").strip()
    sql = ("SELECT c.*, p.policy_no, p.product, p.coverage, u.full_name, u.username "
           "FROM claims c JOIN insurance_policies p ON p.id = c.policy_id "
           "JOIN users u ON u.id = c.user_id")
    params = []
    if status in CLAIM_STATUSES:
        sql += " WHERE c.status = ?"
        params.append(status)
    sql += " ORDER BY c.created_at DESC"
    rows = query(sql, params)
    totals = query("SELECT status, COUNT(*) AS n, COALESCE(SUM(amount),0) AS total "
                   "FROM claims GROUP BY status")
    return _render("admin/claims.html", rows=rows, status=status,
                   statuses=CLAIM_STATUSES, totals=totals,
                   can_review=_can("claims.review"))


@bp.get("/claims/<int:claim_id>/attachment")
@admin_access("claims.read")
def claim_attachment(claim_id):
    claim = query("SELECT * FROM claims WHERE id = ?", (claim_id,), one=True)
    if not claim or not claim["attachment"]:
        abort(404)
    path = safe_join_upload(os.path.join("claims", claim["attachment"]))
    if not os.path.isfile(path):
        abort(404)
    audit("admin.claim.attachment", f"claim_id={claim_id}")
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(claim["attachment"]))


@bp.post("/claims/<int:claim_id>/review")
@admin_access("claims.review")
def claim_review(claim_id):
    csrf_verify()
    claim = query("SELECT * FROM claims WHERE id = ?", (claim_id,), one=True)
    if not claim:
        abort(404)
    decision = (request.form.get("decision") or "").strip()
    note = (request.form.get("note") or "").strip()[:1000]
    if decision not in ("approved", "rejected"):
        abort(400)

    execute("UPDATE claims SET status = ?, admin_note = ?, reviewed_by = ?, "
            "reviewed_at = datetime('now') WHERE id = ?",
            (decision, note or None, current_admin()["id"], claim_id))
    audit("admin.claim.review", f"claim_id={claim_id} decision={decision} "
                                f"amount={claim['amount']}")
    flash(f"Klaim {claim['claim_no']} ditandai {decision}.", "success")
    return redirect(url_for("admin.claims",
                            status=(request.form.get("status") or "submitted")))


# ---------------------------------------------------------------------------
# Semua transaksi + ekspor
# ---------------------------------------------------------------------------
def _tx_rows(q, start, end, account):
    policy = current_policy()
    sql = (
        "SELECT t.*, a.account_number, u.full_name, u.username "
        "FROM transactions t JOIN accounts a ON a.id = t.account_id "
        "JOIN users u ON u.id = a.user_id WHERE 1=1"
    )
    params = []

    if policy.is_vulnerable("sqli_transactions") and not policy.is_hard:
        # VULN: sqli_transactions — filter back-office juga dikonkatenasi.
        # Payload: q=' OR '1'='1
        if q:
            sql += (f" AND (t.description LIKE '%{q}%' "
                    f"OR t.counterparty_name LIKE '%{q}%' OR t.ref_no LIKE '%{q}%')")
        if account:
            sql += f" AND a.account_number = '{account}'"
        if start:
            sql += f" AND t.created_at >= '{start}'"
        if end:
            sql += f" AND t.created_at <= '{end} 23:59:59'"
        sql += " ORDER BY t.created_at DESC, t.id DESC"
        return get_db().execute(sql).fetchall()

    if q:
        like = f"%{q}%"
        sql += (" AND (t.description LIKE ? OR t.counterparty_name LIKE ? "
                "OR t.ref_no LIKE ?)")
        params.extend([like, like, like])
    if account:
        sql += " AND a.account_number = ?"
        params.append(account)

    if policy.is_vulnerable("sqli_transactions"):
        # VULN: sqli_transactions (hard) — hanya rentang tanggal yang masih
        # dirangkai ke SQL (celah halus, error-based / time-based blind).
        if start:
            sql += f" AND t.created_at >= '{start}'"
        if end:
            sql += f" AND t.created_at <= '{end} 23:59:59'"
    else:
        # FIX: seluruh parameter terikat.
        if start:
            sql += " AND t.created_at >= ?"
            params.append(f"{start} 00:00:00")
        if end:
            sql += " AND t.created_at <= ?"
            params.append(f"{end} 23:59:59")

    sql += " ORDER BY t.created_at DESC, t.id DESC"
    return get_db().execute(sql, params).fetchall()


@bp.get("/transactions")
@admin_access("transactions.read")
def transactions():
    q = (request.args.get("q") or "").strip()
    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()
    account = (request.args.get("account") or "").strip()
    page = request.args.get("page", 1, type=int)

    try:
        rows = _tx_rows(q, start, end, account)
        error = None
    except sqlite3.Error as exc:
        rows = []
        error = (f"Query error: {exc}"
                 if current_policy().is_vulnerable("verbose_errors") else
                 "Pencarian gagal diproses.")

    page_data = paginate(rows, page, PAGE_SIZE)
    total_in = sum(r["amount"] for r in rows if r["direction"] == "IN")
    total_out = sum(r["amount"] for r in rows if r["direction"] == "OUT")
    return _render("admin/transactions.html", rows=page_data["items"],
                   page=page_data, q=q, start=start, end=end, account=account,
                   total_in=total_in, total_out=total_out, total_count=len(rows),
                   error=error)


@bp.get("/transactions/export.csv")
@admin_access("transactions.read")
def transactions_export():
    rows = _tx_rows((request.args.get("q") or "").strip(),
                    (request.args.get("start") or "").strip(),
                    (request.args.get("end") or "").strip(),
                    (request.args.get("account") or "").strip())
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ref_no", "tanggal", "rekening", "nasabah", "tipe", "arah",
                     "nominal", "lawan", "deskripsi", "status"])
    for row in rows:
        writer.writerow([row["ref_no"], row["created_at"], row["account_number"],
                         row["username"], row["tx_type"], row["direction"],
                         row["amount"], row["counterparty_name"],
                         row["description"], row["status"]])
    audit("admin.transactions.export", f"rows={len(rows)}")
    return _send_csv(buf.getvalue(), f"transaksi-{datetime.now():%Y%m%d}.csv")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
@bp.get("/audit")
@admin_access("audit.read")
def audit_log():
    q = (request.args.get("q") or "").strip()
    action = (request.args.get("action") or "").strip()
    page = request.args.get("page", 1, type=int)

    sql = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    if q:
        sql += " AND (actor LIKE ? OR detail LIKE ? OR action LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like])
    if action:
        sql += " AND action = ?"
        params.append(action)
    sql += " ORDER BY created_at DESC, id DESC LIMIT 600"
    rows = query(sql, params)
    page_data = paginate(rows, page, 40)
    actions = [r["action"] for r in query(
        "SELECT DISTINCT action FROM audit_logs ORDER BY action")]
    return _render("admin/audit.html", rows=page_data["items"], page=page_data,
                   q=q, action=action, actions=actions)


# ---------------------------------------------------------------------------
# Tiket dukungan
# ---------------------------------------------------------------------------
@bp.get("/tickets")
@admin_access("tickets.manage")
def tickets():
    status = (request.args.get("status") or "").strip()
    sql = ("SELECT t.*, u.full_name, u.username, "
           "(SELECT COUNT(*) FROM ticket_comments c WHERE c.ticket_id = t.id) "
           "AS comment_count FROM tickets t JOIN users u ON u.id = t.user_id")
    params = []
    if status in TICKET_STATUSES:
        sql += " WHERE t.status = ?"
        params.append(status)
    sql += " ORDER BY t.updated_at DESC"
    rows = query(sql, params)
    return _render("admin/tickets.html", rows=rows, status=status,
                   statuses=TICKET_STATUSES)


@bp.get("/tickets/<int:ticket_id>")
@admin_access("tickets.manage")
def ticket_detail(ticket_id):
    ticket = query(
        "SELECT t.*, u.full_name, u.username, u.email FROM tickets t "
        "JOIN users u ON u.id = t.user_id WHERE t.id = ?",
        (ticket_id,), one=True,
    )
    if not ticket:
        abort(404)
    comments = query(
        "SELECT c.* FROM ticket_comments c WHERE c.ticket_id = ? "
        "ORDER BY c.created_at, c.id", (ticket_id,),
    )
    return _render("admin/ticket_detail.html", ticket=ticket, comments=comments,
                   statuses=TICKET_STATUSES)


@bp.post("/tickets/<int:ticket_id>/comment")
@admin_access("tickets.manage")
def ticket_comment(ticket_id):
    csrf_verify()
    ticket = query("SELECT * FROM tickets WHERE id = ?", (ticket_id,), one=True)
    if not ticket:
        abort(404)
    body = (request.form.get("body") or "").strip()
    if not body:
        flash("Komentar tidak boleh kosong.", "error")
        return redirect(url_for("admin.ticket_detail", ticket_id=ticket_id))

    admin = current_admin()
    is_internal = 1 if request.form.get("is_internal") else 0
    execute("INSERT INTO ticket_comments(ticket_id, user_id, author_name, body, "
            "is_internal) VALUES(?,?,?,?,?)",
            (ticket_id, admin["id"], f"{admin['full_name']} (admin)", body,
             is_internal))
    execute("UPDATE tickets SET updated_at = datetime('now'), "
            "status = CASE WHEN status = 'open' THEN 'in_progress' ELSE status END "
            "WHERE id = ?", (ticket_id,))
    audit("admin.ticket.comment", f"ticket={ticket['ticket_no']} internal={is_internal}")
    flash("Balasan dikirim.", "success")
    return redirect(url_for("admin.ticket_detail", ticket_id=ticket_id))


@bp.post("/tickets/<int:ticket_id>/status")
@admin_access("tickets.manage")
def ticket_status(ticket_id):
    csrf_verify()
    status = (request.form.get("status") or "").strip()
    if status not in TICKET_STATUSES:
        abort(400)
    execute("UPDATE tickets SET status = ?, updated_at = datetime('now') WHERE id = ?",
            (status, ticket_id))
    audit("admin.ticket.status", f"ticket_id={ticket_id} status={status}")
    flash("Status tiket diperbarui.", "success")
    return redirect(url_for("admin.ticket_detail", ticket_id=ticket_id))


# ---------------------------------------------------------------------------
# Pengaturan
# ---------------------------------------------------------------------------
@bp.route("/settings", methods=["GET", "POST"])
@admin_access("settings.manage")
def settings():
    policy = current_policy()
    if request.method == "POST":
        csrf_verify()
        candidates = {k: v for k, v in request.form.items() if k != "csrf_token"}
        if policy.level_is_patched:
            # FIX: hanya kunci yang memang operasional yang boleh diubah.
            candidates = {k: v for k, v in candidates.items()
                          if k in SAFE_SETTING_KEYS}
        elif policy.is_hard:
            # VULN: mass_assignment (hard) — blokir dilakukan dengan blacklist
            # nama kunci, sehingga kunci baru tetap bisa disisipkan.
            candidates = {k: v for k, v in candidates.items()
                          if not k.startswith("flag_")}
        # easy/medium: seluruh kunci settings dapat ditulis (termasuk
        # webhook_secret dan flag panel admin).
        changed = []
        for key, value in candidates.items():
            set_setting(key, value)
            changed.append(key)
        audit("admin.settings.update", f"keys={','.join(sorted(changed))}")
        flash(f"{len(changed)} pengaturan disimpan.", "success")
        return redirect(url_for("admin.settings"))

    rows = query("SELECT * FROM settings ORDER BY key")
    return _render("admin/settings.html", rows=rows, policy=policy,
                   safe_keys=SAFE_SETTING_KEYS)


# ---------------------------------------------------------------------------
# Penyimpanan berkas (bekas unggahan)
# ---------------------------------------------------------------------------
@bp.get("/files")
@admin_access("files.read")
def files():
    name = request.args.get("name") or ""
    if not name:
        root = current_app.config["UPLOAD_DIR"]
        entries = []
        for base, _dirs, names in os.walk(root):
            for fname in names:
                full = os.path.join(base, fname)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                entries.append({"name": rel, "size": size})
        entries.sort(key=lambda e: e["name"])
        return _render("admin/files.html", entries=entries[:400], name="")

    # VULN: path_traversal — safe_join_upload membiarkan `../` keluar dari
    # direktori unggahan pada easy/medium.
    # Payload: /admin/files?name=../../../../etc/passwd
    path = safe_join_upload(name)
    if not os.path.isfile(path):
        abort(404)
    audit("admin.files.read", f"name={name}")
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(name) or "file.bin")


# ---------------------------------------------------------------------------
# Diagnostik jaringan — command injection
# ---------------------------------------------------------------------------
# Karakter yang disaring pada level medium (blacklist sengaja tidak lengkap).
MEDIUM_SHELL_BLACKLIST = (";", "&&", "||", "`", "$(")


@bp.route("/diagnostics", methods=["GET", "POST"])
@admin_access("diagnostics.run")
def diagnostics():
    policy = current_policy()
    host = (request.args.get("host") or "").strip()
    output = None
    command = None
    error = None

    if request.method == "POST":
        csrf_verify()
        host = (request.form.get("host") or "").strip()

        if policy.is_vulnerable("command_injection"):
            if policy.is_medium and any(b in host for b in MEDIUM_SHELL_BLACKLIST):
                # VULN: command_injection (medium) — blacklist hanya menyaring
                # `;`, `&&`, `||`, backtick dan `$(`. Pipe tunggal dan `&`
                # tunggal lolos: 127.0.0.1 | echo PWNED
                error = "Karakter tidak diizinkan oleh filter."
            else:
                # VULN: command_injection (easy) — input masuk ke shell tanpa
                # penyaringan sama sekali.
                # Payload: 127.0.0.1; id   atau   127.0.0.1 | cat /etc/passwd
                command = f"ping -c 1 {host}"
                try:
                    output = subprocess.getoutput(command)
                except Exception as exc:  # noqa: BLE001 - lab only
                    output = f"Gagal menjalankan perintah: {exc}"
                audit("admin.diagnostics.ping", f"host={host}")
        else:
            # FIX: argv list, shell dimatikan, dan host divalidasi ketat.
            if not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", host or ""):
                error = "Host hanya boleh berisi huruf, angka, titik, titik dua, dan tanda hubung."
            else:
                command = "ping -c 1 -W 2 " + host
                try:
                    proc = subprocess.run(["ping", "-c", "1", "-W", "2", host],
                                          capture_output=True, text=True, timeout=10,
                                          shell=False)
                    output = (proc.stdout or "") + (proc.stderr or "")
                except FileNotFoundError:
                    error = "Utilitas ping tidak tersedia pada sistem ini."
                except subprocess.TimeoutExpired:
                    error = "Ping melewati batas waktu."
                audit("admin.diagnostics.ping", f"host={host}")

    history = query("SELECT * FROM audit_logs WHERE action = 'admin.diagnostics.ping' "
                    "ORDER BY id DESC LIMIT 8")
    return _render("admin/diagnostics.html", host=host, output=output,
                   command=command, error=error, history=history,
                   vulnerable=policy.is_vulnerable("command_injection"))


# ---------------------------------------------------------------------------
# Ekspor laporan
# ---------------------------------------------------------------------------
def _send_csv(text, filename):
    return current_app.response_class(
        text, mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@bp.get("/reports")
@admin_access("reports.export")
def reports():
    summary = {
        "users": query("SELECT COUNT(*) AS n FROM users", one=True)["n"],
        "accounts": query("SELECT COUNT(*) AS n FROM accounts", one=True)["n"],
        "balance": query("SELECT COALESCE(SUM(balance),0) AS n FROM accounts",
                         one=True)["n"],
        "transactions": query("SELECT COUNT(*) AS n FROM transactions", one=True)["n"],
        "claims_pending": query("SELECT COUNT(*) AS n FROM claims WHERE "
                                "status='submitted'", one=True)["n"],
    }
    return _render("admin/reports.html", summary=summary)


@bp.get("/reports/export")
@admin_access("reports.export")
def reports_export():
    kind = (request.args.get("type") or "users").strip()
    if kind == "users":
        rows = query(
            "SELECT u.id, u.username, u.email, u.full_name, r.name AS role, "
            "u.kyc_status, u.is_active, u.created_at, "
            "(SELECT COALESCE(SUM(a.balance),0) FROM accounts a "
            "WHERE a.user_id = u.id) AS total_balance "
            "FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.id"
        )
        header = ["id", "username", "email", "full_name", "role", "kyc_status",
                  "is_active", "created_at", "total_balance"]
    elif kind == "claims":
        rows = query(
            "SELECT c.claim_no, c.amount, c.status, c.created_at, p.policy_no, "
            "u.username, c.admin_note FROM claims c "
            "JOIN insurance_policies p ON p.id = c.policy_id "
            "JOIN users u ON u.id = c.user_id ORDER BY c.id"
        )
        header = ["claim_no", "amount", "status", "created_at", "policy_no",
                  "username", "admin_note"]
    elif kind == "audit":
        rows = query("SELECT created_at, actor, action, detail, ip FROM audit_logs "
                     "ORDER BY id DESC LIMIT 2000")
        header = ["created_at", "actor", "action", "detail", "ip"]
    else:
        abort(400, description="Tipe laporan tidak dikenal.")

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for row in rows:
        writer.writerow([row[h] for h in header])
    audit("admin.reports.export", f"type={kind} rows={len(rows)}")
    return _send_csv(buf.getvalue(), f"laporan-{kind}-{datetime.now():%Y%m%d}.csv")
