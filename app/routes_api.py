"""REST API v1: autentikasi JWT dan data nasabah untuk aplikasi mitra.

Latihan pada modul ini:
  * weak_jwt          — secret lemah ("nusabank123"), token tanpa kedaluwarsa,
                        dan header alg:none diterima.
  * permissive_cors   — ACAO mencerminkan Origin apa pun + credentials.
  * api_no_rate_limit — endpoint token bisa di-brute force tanpa batas.
"""

import jwt
from flask import Blueprint, g, jsonify, render_template, request

from .db import query
from .lab import current_policy
from .security import (client_ip, jwt_decode, jwt_encode, rate_limit_check,
                       verify_password)
from .utils import audit

bp = Blueprint("api", __name__)

API_PREFIX = "/api/v1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _error(message, status=400, code=None):
    payload = {"ok": False, "error": message}
    if code:
        payload["code"] = code
    return jsonify(payload), status


def _bearer_token():
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    return header[7:].strip() or None


def _api_user():
    """Resolve the JWT bearer token to a user row, or return an error tuple."""
    token = _bearer_token()
    if not token:
        return None, _error("Token Bearer wajib disertakan.", 401, "missing_token")
    try:
        payload = jwt_decode(token)
    except jwt.ExpiredSignatureError:
        return None, _error("Token sudah kedaluwarsa.", 401, "token_expired")
    except jwt.InvalidTokenError:
        return None, _error("Token tidak valid.", 401, "invalid_token")

    subject = payload.get("sub")
    try:
        user_id = int(subject)
    except (TypeError, ValueError):
        return None, _error("Klaim sub tidak valid.", 401, "invalid_token")

    # VULN: weak_jwt — no audience/issuer/scope check, so any token signed with
    # the weak secret (or unsigned with alg:none) impersonates any user id.
    user = query(
        "SELECT u.*, r.name AS role FROM users u "
        "JOIN roles r ON r.id = u.role_id WHERE u.id = ?",
        (user_id,),
        one=True,
    )
    if not user or not user["is_active"]:
        return None, _error("Pengguna tidak ditemukan.", 401, "invalid_token")
    return user, None


def _account_payload(row):
    return {
        "account_number": row["account_number"],
        "account_type": row["account_type"],
        "currency": row["currency"],
        "balance": row["balance"],
        "status": row["status"],
    }


def _transaction_payload(row):
    return {
        "reference": row["ref_no"],
        "type": row["tx_type"],
        "direction": row["direction"],
        "amount": row["amount"],
        "description": row["description"],
        "status": row["status"],
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
@bp.after_request
def _cors(response):
    policy = current_policy()
    origin = request.headers.get("Origin")
    if origin and policy.is_vulnerable("permissive_cors"):
        # VULN: permissive_cors — reflect any origin and allow credentials, so
        # a malicious site can read authenticated API responses.
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    elif origin == request.host_url.rstrip("/"):
        # FIX: same-origin only; no wildcard and no credentials for others.
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------
@bp.get(API_PREFIX + "/ping")
def ping():
    return jsonify({
        "ok": True,
        "service": "NusaBank API",
        "version": "v1",
        "docs": "/api-docs",
        "lab_level": current_policy().level,
    })


@bp.post(API_PREFIX + "/auth/token")
def auth_token():
    if not rate_limit_check(f"api-auth:{client_ip()}", limit=10, window_seconds=60):
        return _error("Terlalu banyak percobaan. Coba lagi nanti.", 429, "rate_limited")

    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return _error("username dan password wajib diisi.", 400, "missing_credentials")

    user = query(
        "SELECT u.*, r.name AS role FROM users u "
        "JOIN roles r ON r.id = u.role_id WHERE u.username = ?",
        (username,),
        one=True,
    )
    if not user or not verify_password(password, user["password_hash"]):
        # VULN: user_enumeration — the response distinguishes an unknown user
        # from a wrong password on easy/medium.
        policy = current_policy()
        if policy.is_vulnerable("user_enumeration") and not user:
            return _error("Username tidak terdaftar.", 401, "unknown_user")
        return _error("Username atau password salah.", 401, "invalid_credentials")
    if not user["is_active"]:
        return _error("Akun tidak aktif.", 403, "account_disabled")

    token = jwt_encode({"sub": str(user["id"]), "username": user["username"],
                        "role": user["role"]})
    audit("api.login", f"user={user['username']} via=api")
    return jsonify({
        "ok": True,
        "token_type": "Bearer",
        "access_token": token,
        "expires_in": 1800,
        "user": {"id": user["id"], "username": user["username"],
                 "full_name": user["full_name"]},
    })


# ---------------------------------------------------------------------------
# Authenticated endpoints
# ---------------------------------------------------------------------------
@bp.get(API_PREFIX + "/balance")
def balance():
    if not rate_limit_check(f"api:{client_ip()}", limit=60, window_seconds=60):
        return _error("Terlalu banyak permintaan.", 429, "rate_limited")
    user, err = _api_user()
    if err:
        return err

    wanted = request.args.get("account_id", type=int)
    if wanted:
        account = query("SELECT * FROM accounts WHERE id = ?", (wanted,), one=True)
        if not account:
            return _error("Rekening tidak ditemukan.", 404, "not_found")
        # VULN: idor_transactions — any valid token may read any account by id.
        # FIX: the account must belong to the token subject.
        if (not current_policy().is_vulnerable("idor_transactions")
                and account["user_id"] != user["id"]):
            return _error("Anda tidak berhak atas rekening ini.", 403, "forbidden")
        return jsonify({"ok": True, "account": _account_payload(account)})

    accounts = query("SELECT * FROM accounts WHERE user_id = ? ORDER BY id",
                     (user["id"],))
    return jsonify({"ok": True,
                    "accounts": [_account_payload(a) for a in accounts]})


@bp.get(API_PREFIX + "/transactions")
def transactions():
    if not rate_limit_check(f"api:{client_ip()}", limit=60, window_seconds=60):
        return _error("Terlalu banyak permintaan.", 429, "rate_limited")
    user, err = _api_user()
    if err:
        return err

    limit = min(max(request.args.get("limit", 20, type=int), 1), 100)
    wanted = request.args.get("account_id", type=int)

    if wanted:
        account = query("SELECT * FROM accounts WHERE id = ?", (wanted,), one=True)
        if not account:
            return _error("Rekening tidak ditemukan.", 404, "not_found")
        # VULN: idor_transactions — see balance().
        if (not current_policy().is_vulnerable("idor_transactions")
                and account["user_id"] != user["id"]):
            return _error("Anda tidak berhak atas rekening ini.", 403, "forbidden")
        rows = query(
            "SELECT * FROM transactions WHERE account_id = ? "
            "ORDER BY created_at DESC, id DESC LIMIT ?",
            (account["id"], limit),
        )
    else:
        rows = query(
            "SELECT t.* FROM transactions t JOIN accounts a ON a.id = t.account_id "
            "WHERE a.user_id = ? ORDER BY t.created_at DESC, t.id DESC LIMIT ?",
            (user["id"], limit),
        )
    return jsonify({"ok": True, "count": len(rows),
                    "transactions": [_transaction_payload(r) for r in rows]})


@bp.get(API_PREFIX + "/profile")
def profile():
    if not rate_limit_check(f"api:{client_ip()}", limit=60, window_seconds=60):
        return _error("Terlalu banyak permintaan.", 429, "rate_limited")
    user, err = _api_user()
    if err:
        return err

    # VULN: idor_profile — ?user_id= lets a token read any customer profile.
    # FIX: ignore the parameter and always return the token subject.
    target = user
    wanted = request.args.get("user_id", type=int)
    if wanted and current_policy().is_vulnerable("idor_profile"):
        target = query("SELECT * FROM users WHERE id = ?", (wanted,), one=True)
        if not target:
            return _error("Pengguna tidak ditemukan.", 404, "not_found")

    return jsonify({
        "ok": True,
        "profile": {
            "id": target["id"],
            "username": target["username"],
            "full_name": target["full_name"],
            "email": target["email"],
            "phone": target["phone"],
            "address": target["address"],
            "kyc_status": target["kyc_status"],
            "created_at": target["created_at"],
        },
    })


# ---------------------------------------------------------------------------
# Developer documentation page
# ---------------------------------------------------------------------------
@bp.get("/api-docs")
def docs():
    return render_template("api/docs.html", api_prefix=API_PREFIX,
                           lab_level=current_policy().level)
