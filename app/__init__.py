"""NusaBank application factory."""

import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, g, render_template, session

from .lab import current_policy


def create_app(overrides=None):
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    app.config.update(
        BASE_DIR=base_dir,
        DB_PATH=os.environ.get("NUSABANK_DB", os.path.join(base_dir, "db", "nusabank.db")),
        UPLOAD_DIR=os.environ.get("NUSABANK_UPLOADS", os.path.join(base_dir, "uploads")),
        DATA_DIR=os.path.join(base_dir, "data"),
        SECRET_KEY=os.environ.get("NUSABANK_SECRET", "nusabank-dev-secret-change-me"),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,  # 8 MB
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        TEMPLATES_AUTO_RELOAD=True,
        LAB_LEVEL=current_policy().level,
        LAB_POLICY=current_policy(),
    )

    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    os.makedirs(app.config["DATA_DIR"], exist_ok=True)
    os.makedirs(os.path.dirname(app.config["DB_PATH"]), exist_ok=True)

    _configure_cookies(app, app.config["LAB_POLICY"])

    if overrides:
        app.config.update(overrides)

    from . import db

    db.init_app(app)
    db.ensure_schema(app)

    register_blueprints(app)
    register_error_handlers(app)
    register_hooks(app)
    return app


def _configure_cookies(app, policy):
    # VULN: insecure_cookies — on easy/medium the session cookie has no
    # HttpOnly/Secure/SameSite flags, so XSS can steal it and it travels on
    # plain HTTP.
    # FIX: HttpOnly + SameSite=Lax + Secure (Secure can be disabled locally
    # with NUSABANK_COOKIE_SECURE=0 if a browser refuses it on http://127.0.0.1).
    secure = not policy.is_vulnerable("insecure_cookies")
    if os.environ.get("NUSABANK_COOKIE_SECURE", "1") == "0":
        secure = False
    app.config.update(
        SESSION_COOKIE_HTTPONLY=not policy.is_vulnerable("insecure_cookies"),
        SESSION_COOKIE_SECURE=secure,
        SESSION_COOKIE_SAMESITE=None if policy.is_vulnerable("insecure_cookies") else "Lax",
        SESSION_COOKIE_NAME="nusabank_session",
    )


def register_blueprints(app):
    from .routes_public import bp as public_bp
    from .routes_auth import bp as auth_bp
    from .routes_dashboard import bp as dash_bp
    from .routes_transactions import bp as tx_bp
    from .routes_uploads import bp as up_bp
    from .routes_claims import bp as claim_bp
    from .routes_tickets import bp as ticket_bp
    from .routes_webhook import bp as hook_bp
    from .routes_api import bp as api_bp
    from .routes_admin import bp as admin_bp

    for bp in (public_bp, auth_bp, dash_bp, tx_bp, up_bp, claim_bp, ticket_bp,
               hook_bp, api_bp, admin_bp):
        app.register_blueprint(bp)


def register_error_handlers(app):
    from flask import request

    def render_error(code, title, message):
        policy = current_policy()
        detail = None
        if policy.is_vulnerable("verbose_errors"):
            # VULN: verbose_errors — internal detail is shown to the client.
            detail = f"Request: {request.method} {request.path} | Level: {policy.level}"
        return render_template(
            f"errors/{code}.html",
            code=code,
            title=title,
            message=message,
            detail=detail,
        ), code

    @app.errorhandler(403)
    def forbidden(_e):
        return render_error(403, "Akses Ditolak",
                            "Anda tidak memiliki izin untuk mengakses halaman ini.")

    @app.errorhandler(404)
    def not_found(_e):
        return render_error(404, "Halaman Tidak Ditemukan",
                            "Halaman yang Anda cari tidak tersedia atau telah dipindahkan.")

    @app.errorhandler(500)
    def server_error(e):
        policy = current_policy()
        if policy.is_vulnerable("verbose_errors"):
            # VULN: verbose_errors — full traceback in the HTTP response.
            import traceback
            tb = traceback.format_exc()
            return render_template(
                "errors/500.html", code=500, title="Terjadi Kesalahan",
                message="Server mengalami error internal.", detail=tb,
            ), 500
        app.logger.exception("Unhandled error: %s", e)
        return render_template(
            "errors/500.html", code=500, title="Terjadi Kesalahan",
            message="Terjadi kesalahan pada server. Silakan coba lagi nanti.",
            detail=None,
        ), 500

    @app.errorhandler(400)
    def bad_request(e):
        return render_error(400, "Permintaan Tidak Valid",
                            getattr(e, "description", "Permintaan tidak dapat diproses."))

    @app.errorhandler(413)
    def too_large(_e):
        return render_error(413, "Berkas Terlalu Besar",
                            "Ukuran berkas melebihi batas 8 MB.")


def register_hooks(app):
    from .db import get_db, get_setting
    from .security import csrf_token

    @app.before_request
    def load_user():
        g.policy = current_policy()
        g.user = None
        uid = session.get("uid")
        if uid is None:
            # Remember-me cookie fallback (weak on easy/medium, see security.py)
            from .security import read_remember_cookie
            uid = read_remember_cookie()
            if uid is not None:
                session["uid"] = uid
        if uid is not None:
            row = get_db().execute(
                "SELECT u.*, r.name AS role FROM users u "
                "JOIN roles r ON r.id = u.role_id WHERE u.id = ?",
                (uid,),
            ).fetchone()
            if row and row["is_active"]:
                g.user = dict(row)
            else:
                session.clear()

    @app.context_processor
    def inject_globals():
        from .utils import rupiah

        policy = g.get("policy", app.config["LAB_POLICY"])
        return {
            "lab_level": policy.level,
            "lab_policy": policy,
            "lab_level_text": policy.describe(),
            "active_user": g.get("user"),
            "site_name": get_setting("site_name", "NusaBank"),
            "site_tagline": get_setting("site_tagline", "Bank Digital Indonesia"),
            "csrf_token": csrf_token,
            "rupiah": rupiah,
            "now_year": datetime.now().year,
        }

    @app.template_filter("rupiah")
    def rupiah_filter(value):
        from .utils import rupiah
        return rupiah(value)

    @app.template_filter("tanggal")
    def tanggal_filter(value):
        """Format an ISO/SQL timestamp for display (Indonesian short date)."""
        if not value:
            return "-"
        text = str(value)[:19].replace("T", " ")
        try:
            dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return str(value)[:10]
        months = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun",
                  "Jul", "Agu", "Sep", "Okt", "Nov", "Des"]
        return f"{dt.day:02d} {months[dt.month - 1]} {dt.year}"

    @app.after_request
    def security_headers(resp):
        policy = current_policy()

        if policy.is_vulnerable("verbose_server_header"):
            # VULN: verbose_server_header — stack fingerprinting.
            resp.headers["X-Powered-By"] = "Flask/3.0.3 Python/3.11 Werkzeug/3.0.3"
        else:
            resp.headers["X-Powered-By"] = "NusaBank Core"
            resp.headers["Server"] = "NusaBank Gateway"

        if not policy.is_vulnerable("missing_security_headers"):
            # FIX: standard security headers. The hard level intentionally
            # allows inline scripts (documented subtle weakness); patched is strict.
            if policy.level_is_patched:
                csp = (
                    "default-src 'self'; img-src 'self' data:; "
                    "style-src 'self'; script-src 'self'; "
                    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                )
            else:
                csp = (
                    "default-src 'self'; img-src 'self' data:; "
                    "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                )
            resp.headers.setdefault("Content-Security-Policy", csp)
            resp.headers.setdefault("X-Frame-Options", "DENY")
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
            resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
            resp.headers.setdefault(
                "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
            )
        return resp