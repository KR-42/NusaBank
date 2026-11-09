"""Shared view helpers: decorators, formatting, audit trail."""

import functools
from datetime import datetime

from flask import abort, g, redirect, request, session, url_for

from .db import log_audit
from .lab import current_policy


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not g.get("user"):
            # Open redirect target is preserved through the ?next= parameter.
            return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user = g.get("user")
        policy = current_policy()

        if policy.is_vulnerable("admin_no_role_check"):
            # VULN: admin_no_role_check — any authenticated user is treated as
            # an administrator when accessing /admin (horizontal/vertical
            # privilege escalation through direct URL access).
            if not user:
                return redirect(url_for("auth.login", next=request.path))
            return view(*args, **kwargs)

        # FIX: verify the server-side role on every request.
        if not user:
            return redirect(url_for("auth.login", next=request.path))
        if user["role"] != "admin":
            log_audit("admin.access_denied", request.path, user_id=user["id"],
                      actor=user["username"])
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def current_user():
    return g.get("user")


def is_admin_user(user):
    """Any of the three back-office roles (admin, admin_cs, admin_finance)."""
    return bool(user) and str(user.get("role") or "").startswith("admin")


def rupiah(value):
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        return "Rp 0"
    sign = "-" if value < 0 else ""
    return f"{sign}Rp {abs(value):,}".replace(",", ".")


def parse_date(value, default=None):
    if not value:
        return default
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return default


def is_safe_redirect(target):
    """Only allow same-origin relative paths."""
    if not target:
        return False
    if not target.startswith("/") or target.startswith("//"):
        return False
    return True


def audit(action, detail="", user=None):
    user = user or g.get("user")
    log_audit(
        action,
        detail,
        user_id=user["id"] if user else None,
        actor=user["username"] if user else "anonymous",
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )


def paginate(rows, page, per_page=15):
    page = max(int(page or 1), 1)
    total = len(rows)
    start = (page - 1) * per_page
    return {
        "items": rows[start:start + per_page],
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": max((total + per_page - 1) // per_page, 1),
    }


def json_ok(**payload):
    return {"success": True, **payload}


def json_err(message, code="error"):
    return {"success": False, "error": code, "message": message}