"""Passwords, sessions, CSRF, JWT and upload helpers gated by LAB_LEVEL."""

import hashlib
import hmac
import os
import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from flask import abort, current_app, request, session

from .lab import current_policy, weak_jwt_secret

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
MIN_PASSWORD_LEN = 12
STRONG_PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$")
WEAK_PASSWORDS = {"password", "123456", "12345678", "qwerty", "admin", "nusabank", "letmein"}


def hash_password(password):
    policy = current_policy()
    if policy.is_vulnerable("weak_password_hash"):
        # VULN: weak_password_hash — MD5 without a salt, crackable in seconds.
        # FIX: bcrypt/argon2 with a per-password salt (else-branch below).
        return "md5:" + hashlib.md5(password.encode("utf-8")).hexdigest()
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password, stored_hash):
    if not stored_hash:
        return False
    try:
        if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
            return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        # Legacy weak hashes kept only for the lab (md5:hex on easy seed users)
        if stored_hash.startswith("md5:"):
            return hmac.compare_digest(
                stored_hash[4:], hashlib.md5(password.encode()).hexdigest()
            )
    except (ValueError, TypeError):
        return False
    return False


def password_policy_error(password, username=None, email=None):
    policy = current_policy()
    if policy.is_vulnerable("weak_password_policy"):
        # VULN: weak_password_policy — any 1-character password accepted.
        return None
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password minimal {MIN_PASSWORD_LEN} karakter."
    if not STRONG_PASSWORD_RE.match(password):
        return "Password harus memuat huruf besar, huruf kecil, angka, dan simbol."
    if password.lower() in WEAK_PASSWORDS:
        return "Password terlalu umum dan mudah ditebak."
    if username and username.lower() in password.lower():
        return "Password tidak boleh mengandung username."
    if email and email.split("@")[0].lower() in password.lower():
        return "Password tidak boleh mengandung nama email."
    return None


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
def csrf_token():
    policy = current_policy()
    if policy.is_vulnerable("csrf"):
        return "nusabank-csrf-static-token"
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def csrf_verify():
    """Call at the start of every state-changing view."""
    policy = current_policy()
    if policy.is_vulnerable("csrf"):
        return  # easy/medium: token rendered but never checked
    if policy.is_hard and "multipart/form-data" in (request.content_type or ""):
        # VULN: csrf (hard) — the token check is accidentally skipped for
        # multipart bodies, a common framework integration bug.
        return
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
        abort(400, description="CSRF token tidak valid atau kedaluwarsa.")


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def rotate_session(user_id, remember=False):
    """Create the logged-in session state."""
    policy = current_policy()
    session.permanent = True
    if policy.is_vulnerable("session_fixation"):
        # VULN: session_fixation — SID is not rotated after authentication, so
        # an attacker who presets a cookie can reuse it post-login.
        session["uid"] = user_id
        session["_fix"] = session.get("_fix", "pre-auth")
        return
    session.clear()
    session["uid"] = user_id
    session["sess_epoch"] = datetime.now(timezone.utc).isoformat()
    session.permanent = bool(remember)


def logout_session():
    session.clear()


def issue_remember_cookie(user_id):
    """Selector/validator cookie; only used when hardening is enabled."""
    policy = current_policy()
    if policy.is_vulnerable("insecure_remember"):
        # VULN: insecure_remember — the cookie is just the user id, so anyone
        # can forge nb_remember=1 and be logged in as the first user.
        expiry = datetime.now(timezone.utc) + timedelta(days=14)
        return str(user_id), expiry

    selector = secrets.token_urlsafe(9)
    validator = secrets.token_urlsafe(32)
    expiry = datetime.now(timezone.utc) + timedelta(days=14)
    from .db import execute

    execute(
        "INSERT INTO remember_tokens(user_id, selector, validator_hash, expires_at) "
        "VALUES(?,?,?,?)",
        (user_id, selector, _sha256(validator), expiry.isoformat()),
    )
    return f"{selector}:{validator}", expiry


def read_remember_cookie():
    raw = request.cookies.get("nb_remember")
    if not raw or ":" not in raw:
        # VULN: insecure_remember — a bare numeric cookie is trusted as the
        # user id on easy/medium.
        if raw and raw.isdigit() and current_policy().is_vulnerable("insecure_remember"):
            return int(raw)
        return None
    selector, validator = raw.split(":", 1)
    from .db import query

    row = query("SELECT * FROM remember_tokens WHERE selector = ?", (selector,), one=True)
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    if not hmac.compare_digest(row["validator_hash"], _sha256(validator)):
        return None
    return row["user_id"]


def _sha256(value):
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Reset tokens
# ---------------------------------------------------------------------------
def create_reset_token(user):
    policy = current_policy()
    from .db import execute

    if policy.is_vulnerable("predictable_reset_token"):
        # VULN: predictable_reset_token — token derived from user id + date,
        # trivially forgeable without access to the mailbox.
        raw = f"{user['id']}-{datetime.now().strftime('%Y%m%d')}"
    else:
        raw = secrets.token_urlsafe(32)
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    execute("DELETE FROM reset_tokens WHERE user_id = ? AND used = 0", (user["id"],))
    execute(
        "INSERT INTO reset_tokens(user_id, token, expires_at) VALUES(?,?,?)",
        (user["id"], raw, expiry.isoformat()),
    )
    return raw


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def jwt_encode(payload):
    policy = current_policy()
    secret = weak_jwt_secret() if policy.is_vulnerable("weak_jwt") else current_app.config["SECRET_KEY"]
    if policy.is_vulnerable("weak_jwt"):
        # VULN: weak_jwt — unsigned tokens accepted and no expiry on easy/medium.
        return jwt.encode(payload, secret, algorithm="HS256")

    payload = dict(payload)
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=30)
    payload["iat"] = datetime.now(timezone.utc)
    return jwt.encode(payload, secret, algorithm="HS256")


def jwt_decode(token):
    policy = current_policy()
    secret = weak_jwt_secret() if policy.is_vulnerable("weak_jwt") else current_app.config["SECRET_KEY"]
    if policy.is_vulnerable("weak_jwt"):
        # VULN: weak_jwt — unsigned tokens (alg:none) and expired tokens are
        # accepted. PyJWT refuses `none` when a key is supplied, so the lab
        # decodes unsigned tokens with signature verification disabled.
        header = jwt.get_unverified_header(token)
        if header.get("alg") == "none":
            return jwt.decode(token, options={"verify_signature": False,
                                              "verify_exp": False})
        return jwt.decode(token, secret, algorithms=["HS256"],
                          options={"verify_exp": False})
    # FIX: pinned algorithm list, strong secret and mandatory expiry.
    return jwt.decode(token, secret, algorithms=["HS256"],
                      options={"require": ["exp", "sub"]})


# ---------------------------------------------------------------------------
# Input validation & files
# ---------------------------------------------------------------------------
def client_ip():
    policy = current_policy()
    if policy.is_hard:
        # VULN: rate_limiting (hard) — the limiter keys on X-Forwarded-For, which
        # the client controls. Rotating the header resets the counter.
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def valid_account_number(value):
    return bool(re.fullmatch(r"\d{10}", value or ""))


def valid_email(value):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", value or ""))


ALLOWED_EXTS = {"pdf", "jpg", "jpeg", "png"}
ALLOWED_MIME = {"application/pdf", "image/jpeg", "image/png"}
MAGIC = {
    b"%PDF": "pdf",
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
}


def sniff_kind(head):
    for magic, kind in MAGIC.items():
        if head.startswith(magic):
            return kind
    if b"<svg" in head[:512].lower() or b"<?xml" in head[:512].lower():
        return "svg"
    return None


def save_upload(file_storage, subdir="kyc"):
    """Return (stored_name, original_name, mime, size) or raise ValueError."""
    return _store_upload(file_storage, subdir)[:4]


def _store_upload(file_storage, subdir="kyc"):
    """Shared worker. Returns (stored, original, mime, size, raw_bytes)."""
    policy = current_policy()
    original = (file_storage.filename or "file").replace("\\", "/").rsplit("/", 1)[-1]
    raw = file_storage.read()
    if not raw:
        raise ValueError("Berkas kosong.")

    if policy.is_vulnerable("insecure_upload"):
        # VULN: insecure_upload — the client-supplied filename is kept as-is and
        # written under the upload root; there is no magic-byte check.
        #   easy   : no filtering at all.
        #   medium : a blacklist of "dangerous" extensions that is bypassed with
        #            .phtml, .svg or a double extension such as shell.pdf.php.
        bad = (".php", ".py", ".exe", ".sh")
        if policy.is_medium and any(original.lower().endswith(b) for b in bad):
            raise ValueError("Ekstensi tidak diizinkan.")
        target_dir = os.path.join(current_app.config["UPLOAD_DIR"], subdir)
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, original)
        with open(path, "wb") as fh:
            fh.write(raw)
        return original, original, file_storage.mimetype, len(raw), raw

    # FIX: whitelist extension + magic bytes + random stored name.
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_EXTS:
        raise ValueError("Jenis berkas tidak diizinkan (PDF/JPG/PNG).")
    kind = sniff_kind(raw[:1024])
    if kind is None or kind not in ALLOWED_EXTS:
        raise ValueError("Isi berkas tidak sesuai dengan ekstensinya.")
    if file_storage.mimetype not in ALLOWED_MIME:
        raise ValueError("MIME type tidak diizinkan.")
    stored = f"{secrets.token_hex(16)}.{kind}"
    target_dir = os.path.join(current_app.config["UPLOAD_DIR"], subdir)
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(os.path.realpath(target_dir), stored)
    with open(path, "wb") as fh:
        fh.write(raw)
    return stored, original, file_storage.mimetype, len(raw), raw


def safe_join_upload(name):
    """Resolve an upload name, with an intentional traversal branch."""
    policy = current_policy()
    root = os.path.realpath(current_app.config["UPLOAD_DIR"])
    if policy.is_vulnerable("path_traversal"):
        # VULN: path_traversal — os.path.join with user input escapes the root.
        return os.path.join(root, name)
    candidate = os.path.realpath(os.path.join(root, name))
    if os.path.commonpath([root, candidate]) != root:
        abort(403)
    return candidate


def sanitize_text(value, max_len=1000):
    """Strip control characters; escaping is done by Jinja autoescape."""
    if value is None:
        return ""
    value = unicodedata.normalize("NFKC", str(value))
    value = "".join(ch for ch in value if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return value[:max_len]


# ---------------------------------------------------------------------------
# Rate limiting / lockout
# ---------------------------------------------------------------------------
def rate_limit_check(key, limit=10, window_seconds=60):
    """Simple in-memory sliding counter for hardened levels."""
    from collections import defaultdict, deque

    policy = current_policy()
    if policy.is_vulnerable("api_no_rate_limit") and key.startswith("api:"):
        return True  # VULN: api_no_rate_limit
    if policy.level_is_patched or policy.is_hard:
        now = datetime.now(timezone.utc).timestamp()
        bucket = _RATE.setdefault(key, deque())
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
    return True


_RATE = {}


def login_is_locked(user_row):
    policy = current_policy()
    if policy.is_vulnerable("no_account_lockout"):
        return False
    if user_row and user_row["locked_until"]:
        try:
            if datetime.fromisoformat(user_row["locked_until"]) > datetime.now(timezone.utc):
                return True
        except (ValueError, TypeError):
            return False
    return False


def register_login_failure(user_row, threshold=5, lock_minutes=15):
    policy = current_policy()
    if policy.is_vulnerable("no_account_lockout"):
        return
    from .db import execute

    fails = (user_row["failed_logins"] or 0) + 1
    if fails >= threshold:
        until = (datetime.now(timezone.utc) + timedelta(minutes=lock_minutes)).isoformat()
        execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                (fails, until, user_row["id"]))
    else:
        execute("UPDATE users SET failed_logins = ? WHERE id = ?", (fails, user_row["id"]))


def reset_login_failures(user_row):
    from .db import execute

    execute("UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = datetime('now') "
            "WHERE id = ?", (user_row["id"],))