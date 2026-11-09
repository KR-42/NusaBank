"""Pusat bantuan: tiket pengaduan nasabah beserta percakapan (komentar)."""

import secrets

from flask import (Blueprint, abort, flash, g, redirect, render_template, request,
                   url_for)

from .db import execute, query
from .lab import current_policy
from .security import csrf_verify
from .utils import audit, is_admin_user, login_required

bp = Blueprint("tickets", __name__)

CATEGORIES = ("umum", "teknis", "keluhan", "saran")
PRIORITIES = ("low", "normal", "high")
STATUS_LABELS = {"open": "Terbuka", "in_progress": "Diproses", "closed": "Selesai"}


def _ticket_no():
    while True:
        ref = f"TCK-{secrets.randbelow(900000) + 100000}"
        if not query("SELECT 1 FROM tickets WHERE ticket_no = ?", (ref,), one=True):
            return ref


def _load(ticket_id):
    return query(
        "SELECT t.*, u.full_name, u.username FROM tickets t "
        "JOIN users u ON u.id = t.user_id WHERE t.id = ?",
        (ticket_id,),
        one=True,
    )


def _owns(policy, ticket):
    return (policy.is_vulnerable("idor_tickets")
            or ticket["user_id"] == g.user["id"]
            or is_admin_user(g.user))


@bp.get("/support")
@login_required
def index():
    policy = current_policy()
    # Admins see the whole queue; customers only their own tickets.
    if g.user.get("role", "").startswith("admin"):
        tickets = query(
            "SELECT t.*, u.full_name, "
            "(SELECT COUNT(*) FROM ticket_comments c WHERE c.ticket_id = t.id) "
            "AS comment_count FROM tickets t JOIN users u ON u.id = t.user_id "
            "ORDER BY t.updated_at DESC",
        )
    else:
        tickets = query(
            "SELECT t.*, u.full_name, "
            "(SELECT COUNT(*) FROM ticket_comments c WHERE c.ticket_id = t.id) "
            "AS comment_count FROM tickets t JOIN users u ON u.id = t.user_id "
            "WHERE t.user_id = ? ORDER BY t.updated_at DESC",
            (g.user["id"],),
        )
    return render_template("tickets/index.html", tickets=tickets,
                           status_labels=STATUS_LABELS,
                           xss_stored=policy.is_vulnerable("ticket_xss"))


@bp.route("/support/new", methods=["GET", "POST"])
@login_required
def create():
    policy = current_policy()

    if request.method == "POST":
        csrf_verify()
        subject = (request.form.get("subject") or "").strip()
        body = (request.form.get("body") or "").strip()
        category = request.form.get("category") or "umum"
        priority = request.form.get("priority") or "normal"
        if category not in CATEGORIES:
            category = "umum"
        if priority not in PRIORITIES:
            priority = "normal"

        if not subject or not body:
            flash("Subjek dan isi pengaduan wajib diisi.", "error")
            return render_template("tickets/create.html", categories=CATEGORIES,
                                   priorities=PRIORITIES), 400
        if len(subject) > 140:
            subject = subject[:140]

        # VULN: ticket_xss — subject and body are stored verbatim and rendered
        # with |safe on easy/medium. Try: <img src=x onerror=alert(1)>
        # FIX: hard/patched render through Jinja auto-escape (see the template).
        ticket_no = _ticket_no()
        ticket_id = execute(
            "INSERT INTO tickets(ticket_no, user_id, subject, category, priority, "
            "status) VALUES(?,?,?,?,?,?)",
            (ticket_no, g.user["id"], subject, category, priority, "open"),
        )
        execute(
            "INSERT INTO ticket_comments(ticket_id, user_id, author_name, body) "
            "VALUES(?,?,?,?)",
            (ticket_id, g.user["id"], g.user["full_name"], body),
        )
        audit("ticket.create", f"ticket={ticket_no} category={category}")
        flash(f"Tiket {ticket_no} berhasil dibuat.", "success")
        return redirect(url_for("tickets.detail", ticket_id=ticket_id))

    return render_template("tickets/create.html", categories=CATEGORIES,
                           priorities=PRIORITIES,
                           xss_stored=policy.is_vulnerable("ticket_xss"))


@bp.get("/support/<int:ticket_id>")
@login_required
def detail(ticket_id):
    policy = current_policy()
    ticket = _load(ticket_id)
    if not ticket:
        abort(404)

    # VULN: idor_tickets — ticket ids are sequential and never scoped to the
    # session user on easy/medium, exposing other customers' conversations.
    # FIX: compare ticket.user_id with the session user (admins exempt).
    if not _owns(policy, ticket):
        abort(403)

    # VULN: internal_note_exposure — agent-only notes (is_internal = 1) are
    # rendered to the customer on easy/medium/hard. Only `patched` filters them.
    internal_visible = policy.is_vulnerable("internal_note_exposure")
    comments = query(
        "SELECT c.*, u.full_name FROM ticket_comments c "
        "LEFT JOIN users u ON u.id = c.user_id "
        "WHERE c.ticket_id = ? ORDER BY c.created_at, c.id",
        (ticket_id,),
    )
    if not internal_visible:
        comments = [c for c in comments if not c["is_internal"]]

    return render_template("tickets/detail.html", ticket=ticket, comments=comments,
                           status_labels=STATUS_LABELS,
                           xss_stored=policy.is_vulnerable("ticket_xss"))


@bp.post("/support/<int:ticket_id>/comment")
@login_required
def comment(ticket_id):
    policy = current_policy()
    csrf_verify()
    ticket = _load(ticket_id)
    if not ticket:
        abort(404)
    if not _owns(policy, ticket):
        abort(403)
    if ticket["status"] == "closed" and not is_admin_user(g.user):
        flash("Tiket sudah ditutup. Buat tiket baru untuk kendala lanjutan.", "error")
        return redirect(url_for("tickets.detail", ticket_id=ticket_id))

    body = (request.form.get("body") or "").strip()
    if not body:
        flash("Komentar tidak boleh kosong.", "error")
        return redirect(url_for("tickets.detail", ticket_id=ticket_id))

    # VULN: ticket_xss — comment bodies are stored raw and rendered with |safe
    # on easy/medium, giving stored XSS visible to every viewer of the ticket.
    # is_internal is an agent-only flag: customers must never be able to set it.
    if is_admin_user(g.user):
        is_internal = 1 if request.form.get("is_internal") else 0
    elif request.form.get("is_internal") and not policy.level_is_patched:
        # VULN: internal_note_exposure — on easy/medium/hard a customer can
        # flag their own message as an internal note (privilege confusion).
        is_internal = 1
    else:
        is_internal = 0
    execute(
        "INSERT INTO ticket_comments(ticket_id, user_id, author_name, body, is_internal) "
        "VALUES(?,?,?,?,?)",
        (ticket_id, g.user["id"], g.user["full_name"], body, is_internal),
    )
    execute("UPDATE tickets SET updated_at = datetime('now'), "
            "status = CASE WHEN status = 'open' THEN 'in_progress' ELSE status END "
            "WHERE id = ?", (ticket_id,))
    audit("ticket.comment", f"ticket={ticket['ticket_no']} internal={is_internal}")
    flash("Komentar dikirim.", "success")
    return redirect(url_for("tickets.detail", ticket_id=ticket_id))
