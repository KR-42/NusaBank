"""E-wallet: menghubungkan dompet digital mitra lewat webhook (latihan SSRF).

Nasabah mendaftarkan URL callback, lalu server NusaBank memanggil URL tersebut
untuk memverifikasi koneksi dan mengirim notifikasi transaksi. Karena URL
sepenuhnya dikendalikan nasabah, endpoint ini adalah sink SSRF klasik.
"""

import hashlib
import hmac
import ipaddress
import socket
import time
from urllib.parse import urlsplit

import requests
from flask import (Blueprint, abort, flash, g, redirect, render_template, request,
                   url_for)

from .db import execute, get_setting, query
from .lab import current_policy
from .security import csrf_verify
from .utils import audit, login_required

bp = Blueprint("webhook", __name__)

MAX_RESPONSE = 4000
MAX_URL = 500

# Host yang tidak boleh dihubungi pada level `hard` (daftar hitam).
DENY_HOSTS = {"localhost", "0.0.0.0", "::1", "169.254.169.254", "metadata"}
DENY_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                 "172.19.", "172.2", "172.30.", "172.31.", "169.254.")


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------
def _allowlisted(host):
    """Host mitra yang secara eksplisit diizinkan (settings.webhook_allowlist)."""
    raw = get_setting("webhook_allowlist", "partner.nusabank.example.com")
    allowed = {item.strip().lower() for item in (raw or "").split(",") if item.strip()}
    return (host or "").lower().rstrip(".") in allowed


def _public_target(url):
    """Strict policy used by `patched`.

    FIX: only http(s); allowlisted partner hosts are trusted, everything else
    must resolve to a public address. Private, loopback, link-local, reserved,
    multicast and unspecified ranges are rejected after resolution, so DNS
    tricks do not help.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Hanya URL http atau https yang diizinkan."
    host = parsed.hostname
    if not host:
        return False, "URL tidak memuat nama host yang valid."
    if _allowlisted(host):
        return True, None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False, "Port pada URL tidak valid."
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return False, "Nama host tidak dapat diselesaikan."

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
        except ValueError:
            return False, "Alamat IP tujuan tidak valid."
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False, "URL mengarah ke alamat internal/private dan diblokir."
    return True, None


def _hard_target(url):
    """Blacklist-by-name guard used on `hard`.

    VULN: ssrf_webhook (hard) — the hostname is compared as a *string*, never
    resolved, and the comparison has no normalisation. Appending a trailing dot
    ("localhost.", "127.0.0.1.") or using a decimal/octal form resolves to the
    same loopback address while sidestepping the deny list.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Hanya URL http atau https yang diizinkan."
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "URL tidak memuat nama host yang valid."
    if _allowlisted(host):
        return True, None
    if host in DENY_HOSTS or host.startswith(DENY_PREFIXES):
        return False, "URL mengarah ke alamat internal dan diblokir."
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True, None          # bukan IP literal: lolos tanpa resolusi
    # FIX: private/link-local IP literals rejected.
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        return False, "URL mengarah ke alamat internal dan diblokir."
    return True, None


def _target_allowed(policy, url):
    """Level-aware URL policy applied before the server performs a fetch."""
    if not url:
        return False, "URL webhook wajib diisi."
    if len(url) > MAX_URL:
        return False, "URL terlalu panjang."

    if policy.level_is_patched:
        return _public_target(url)

    if policy.is_hard:
        return _hard_target(url)

    if policy.is_medium:
        # VULN: ssrf_webhook (medium) — blacklist string sederhana. Cukup ganti
        # host menjadi 127.0.0.1 (string "localhost" tidak muncul) atau pakai
        # 127.0.0.2 / [::1] untuk melewati filter.
        blocked = ("localhost", "169.254.169.254", "file://")
        if any(item in url.lower() for item in blocked):
            return False, "URL tidak diizinkan (daftar hitam)."
        return True, None

    # VULN: ssrf_webhook (easy) — URL apa pun langsung diambil server.
    # Contoh: http://127.0.0.1:8080/internal/metadata atau file:///app/uploads/legacy/flag.txt
    return True, None


# ---------------------------------------------------------------------------
# Server-side fetch (the SSRF sink)
# ---------------------------------------------------------------------------
def _signature(params):
    secret = get_setting("webhook_secret", "whsec_nusabank_lab_dev").encode()
    message = "&".join(f"{k}={params[k]}" for k in sorted(params))
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()


def _deliver(webhook_id, url):
    """Call the customer-supplied URL from the server and record the result."""
    policy = current_policy()
    params = {"event": "wallet.verify", "webhook_id": str(webhook_id),
              "ts": str(int(time.time()))}
    if not policy.is_vulnerable("ssrf_webhook"):
        # FIX: signed payload so the partner can reject forged callbacks.
        params["sig"] = _signature(params)

    status, body = None, ""
    failed = False
    try:
        resp = requests.get(
            url,
            params=params,
            timeout=4,
            # VULN: ssrf_webhook — redirects are followed, so an allowed host can
            # bounce the request to an internal address.
            allow_redirects=policy.is_vulnerable("ssrf_webhook"),
            headers={"User-Agent": "NusaBank-Webhook/1.0"},
        )
        status = resp.status_code
        body = (resp.text or "")[:MAX_RESPONSE]
    except requests.RequestException as exc:
        failed = True
        if policy.is_vulnerable("verbose_errors"):
            # VULN: verbose_errors — exception detail is shown to the customer.
            body = f"Gagal menghubungi URL: {exc.__class__.__name__}: {exc}"
        else:
            body = "Gagal menghubungi URL tujuan."

    execute(
        "UPDATE webhooks SET last_status = ?, last_body = ?, "
        "last_called_at = datetime('now') WHERE id = ?",
        (status, body, webhook_id),
    )
    execute(
        "INSERT INTO webhook_logs(webhook_id, user_id, url, status, response) "
        "VALUES(?,?,?,?,?)",
        (webhook_id, g.user["id"], url, status, body),
    )
    audit("webhook.call", f"webhook={webhook_id} status={status} url={url[:200]}")
    return {"status": status, "body": body, "url": url, "failed": failed}


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------
def _page(result=None, status=200):
    hooks = query("SELECT * FROM webhooks WHERE user_id = ? ORDER BY id DESC",
                  (g.user["id"],))
    logs = query(
        "SELECT * FROM webhook_logs WHERE user_id = ? ORDER BY id DESC LIMIT 20",
        (g.user["id"],),
    )
    return render_template("wallet/index.html", hooks=hooks, logs=logs,
                           result=result, partner_url=url_for("webhook.partner",
                                                              _external=True)), status


@bp.route("/wallet", methods=["GET", "POST"])
@login_required
def index():
    policy = current_policy()

    if request.method == "POST":
        csrf_verify()
        label = (request.form.get("label") or "").strip()[:60] or "E-Wallet"
        url = (request.form.get("url") or "").strip()
        allowed, reason = _target_allowed(policy, url)
        if not allowed:
            flash(reason, "error")
            return _page(status=400)

        webhook_id = execute(
            "INSERT INTO webhooks(user_id, label, url) VALUES(?,?,?)",
            (g.user["id"], label, url),
        )
        result = _deliver(webhook_id, url)
        if result["failed"]:
            flash("Webhook disimpan, tetapi endpoint tidak dapat dihubungi.", "error")
        else:
            flash(f"Webhook terhubung. Endpoint membalas HTTP {result['status']}.",
                  "success")
        return _page(result=result)

    return _page()


@bp.post("/wallet/<int:webhook_id>/test")
@login_required
def test(webhook_id):
    csrf_verify()
    hook = query("SELECT * FROM webhooks WHERE id = ? AND user_id = ?",
                 (webhook_id, g.user["id"]), one=True)
    if not hook:
        abort(404)

    allowed, reason = _target_allowed(current_policy(), hook["url"])
    if not allowed:
        flash(reason, "error")
        return redirect(url_for("webhook.index"))

    result = _deliver(hook["id"], hook["url"])
    if result["failed"]:
        flash("Endpoint webhook tidak dapat dihubungi.", "error")
    else:
        flash(f"Endpoint membalas HTTP {result['status']}.", "success")
    return _page(result=result)


@bp.post("/wallet/<int:webhook_id>/delete")
@login_required
def delete(webhook_id):
    csrf_verify()
    hook = query("SELECT * FROM webhooks WHERE id = ? AND user_id = ?",
                 (webhook_id, g.user["id"]), one=True)
    if not hook:
        abort(404)
    execute("DELETE FROM webhooks WHERE id = ?", (hook["id"],))
    audit("webhook.delete", f"webhook={webhook_id}")
    flash("Koneksi e-wallet dihapus.", "success")
    return redirect(url_for("webhook.index"))


@bp.get("/wallet/partner")
def partner():
    """Halaman mitra tiruan: menerima callback dan memverifikasi tanda tangannya.

    Dipakai sebagai target webhook yang sah di dalam lab, sehingga latihan
    "hubungkan e-wallet" tetap berfungsi tanpa akses internet.
    """
    args = {k: v for k, v in request.args.items()}
    provided = args.pop("sig", None)
    signature_ok = None
    if provided:
        signature_ok = hmac.compare_digest(provided, _signature(args))
    return render_template("wallet/partner.html", args=args,
                           signature_ok=signature_ok,
                           provided=provided)
