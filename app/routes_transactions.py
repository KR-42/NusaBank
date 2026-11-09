"""Transaksi: transfer, riwayat, filter, ekspor CSV, detail & struk."""

import csv
import io
import random
import sqlite3
import time
from datetime import datetime

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect,
                   render_template, request, url_for)

from .db import execute, get_db, get_setting, query
from .lab import current_policy
from .security import csrf_verify, valid_account_number, verify_password
from .utils import audit, login_required, paginate, rupiah

bp = Blueprint("transactions", __name__)

PAGE_SIZE = 15


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ref_no():
    while True:
        ref = f"TRX-{datetime.now():%Y%m%d}-{random.randint(100000, 999999)}"
        if not query("SELECT 1 FROM transactions WHERE ref_no = ?", (ref,), one=True):
            return ref


def _account_row(account_id):
    return query("SELECT * FROM accounts WHERE id = ?", (account_id,), one=True)


def _owns(user_id, account):
    return bool(account) and account["user_id"] == user_id


def _record(conn, account_id, signed_amount, description, counterparty_name,
            counterparty_account, related_account_id, balance_after, tx_type="transfer"):
    direction = "IN" if signed_amount > 0 else "OUT"
    conn.execute(
        "INSERT INTO transactions(ref_no, account_id, related_account_id, direction, "
        "tx_type, amount, counterparty_name, counterparty_account, description, "
        "category, status, balance_after, created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))",
        (_ref_no(), account_id, related_account_id, direction, tx_type,
         abs(signed_amount), counterparty_name, counterparty_account,
         description, "transfer", "success", balance_after),
    )


# ---------------------------------------------------------------------------
# Transfer
# ---------------------------------------------------------------------------
@bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    policy = current_policy()
    accounts = query("SELECT * FROM accounts WHERE user_id = ? ORDER BY id",
                     (g.user["id"],))

    if request.method == "POST":
        csrf_verify()
        account_id = request.form.get("account_id") or (accounts[0]["id"] if accounts else 0)
        dest_number = (request.form.get("dest_account") or "").strip()
        description = (request.form.get("description") or "").strip()
        pin = request.form.get("pin") or ""

        try:
            amount = int(request.form.get("amount") or 0)
        except ValueError:
            amount = 0

        source = _account_row(account_id)
        if not source:
            abort(404)

        # VULN: idor_transactions — the source account is taken from the form
        # and never compared with the session user on easy/medium/hard.
        if not policy.is_vulnerable("idor_transactions") and not _owns(g.user["id"], source):
            abort(403)

        # VULN: pin_bypass — on easy/medium an empty PIN skips the check.
        if policy.is_vulnerable("pin_bypass"):
            if pin and not verify_password(pin, g.user["pin_hash"]):
                flash("PIN transaksi salah.", "error")
                return render_template("transactions/transfer.html", accounts=accounts), 400
        elif not verify_password(pin, g.user["pin_hash"]):
            flash("PIN transaksi salah.", "error")
            return render_template("transactions/transfer.html", accounts=accounts), 400

        if not valid_account_number(dest_number):
            flash("Nomor rekening tujuan harus 10 digit.", "error")
            return render_template("transactions/transfer.html", accounts=accounts), 400

        dest = query("SELECT * FROM accounts WHERE account_number = ?",
                     (dest_number,), one=True)
        if not dest:
            flash("Rekening tujuan tidak ditemukan.", "error")
            return render_template("transactions/transfer.html", accounts=accounts), 404
        if dest["id"] == source["id"]:
            flash("Tidak dapat transfer ke rekening sendiri.", "error")
            return render_template("transactions/transfer.html", accounts=accounts), 400

        # VULN: negative_transfer — on easy/medium/hard a negative amount is
        # accepted, so the sender's balance grows and the recipient's shrinks.
        if not policy.is_vulnerable("negative_transfer") and amount <= 0:
            flash("Nominal transfer harus lebih dari nol.", "error")
            return render_template("transactions/transfer.html", accounts=accounts), 400

        if not policy.is_vulnerable("negative_transfer"):
            limit = int(get_setting("transfer_limit", "25000000") or 25000000)
            if amount > limit:
                flash(f"Nominal melebihi batas harian {rupiah(limit)}.", "error")
                return render_template("transactions/transfer.html", accounts=accounts), 400

        error = _apply_transfer(source, dest, amount, description)
        if error:
            flash(error, "error")
            return render_template("transactions/transfer.html", accounts=accounts), 400

        audit("transfer.create",
              f"from={source['account_number']} to={dest_number} amount={amount}")
        flash(f"Transfer sebesar {rupiah(amount)} berhasil dikirim.", "success")
        return redirect(url_for("transactions.history",
                                account_id=source["id"]))

    return render_template("transactions/transfer.html", accounts=accounts)


def _apply_transfer(source, dest, amount, description):
    """Move money between two accounts. Returns an error string or None."""
    policy = current_policy()
    conn = get_db()
    description = description or "Transfer antar rekening"

    if policy.is_vulnerable("race_condition"):
        # VULN: race_condition — balance is read, then written later with no
        # transaction/locking. The sleep stands in for the latency a real core
        # banking call would add, and is what makes the window exploitable:
        # N parallel requests all read the same balance and all commit.
        src_balance = _account_row(source["id"])["balance"]
        dest_balance = _account_row(dest["id"])["balance"]
        if amount > 0 and src_balance < amount:
            return "Saldo tidak mencukupi."
        time.sleep(0.08)
        conn.execute("UPDATE accounts SET balance = ? WHERE id = ?",
                     (src_balance - amount, source["id"]))
        conn.execute("UPDATE accounts SET balance = ? WHERE id = ?",
                     (dest_balance + amount, dest["id"]))
        _record(conn, source["id"], -amount, description,
                dest["account_number"], dest["account_number"], dest["id"],
                src_balance - amount)
        _record(conn, dest["id"], amount, description, source["account_number"],
                source["account_number"], source["id"], dest_balance + amount)
        conn.commit()
        return None

    if policy.is_vulnerable("atomic_transactions"):
        # Subtle flaw (hard): the funds check happens *outside* the locking
        # transaction and is not repeated inside it. The short delay stands in
        # for the core-banking round trip a real transfer makes between the
        # check and the write, which is the window two concurrent requests
        # exploit to overdraw the account.
        check_balance = _account_row(source["id"])["balance"]
        if amount > 0 and check_balance < amount:
            return "Saldo tidak mencukupi."
        time.sleep(0.08)

    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError:
        pass  # a transaction is already open on this connection

    try:
        src_balance = conn.execute(
            "SELECT balance FROM accounts WHERE id = ?", (source["id"],)
        ).fetchone()["balance"]
        # FIX: re-check inside the write lock (hard skips this re-check).
        if not policy.is_vulnerable("atomic_transactions"):
            if amount > 0 and src_balance < amount:
                conn.rollback()
                return "Saldo tidak mencukupi."
        dest_balance = conn.execute(
            "SELECT balance FROM accounts WHERE id = ?", (dest["id"],)
        ).fetchone()["balance"]

        conn.execute("UPDATE accounts SET balance = ? WHERE id = ?",
                     (src_balance - amount, source["id"]))
        conn.execute("UPDATE accounts SET balance = ? WHERE id = ?",
                     (dest_balance + amount, dest["id"]))
        _record(conn, source["id"], -amount, description, dest["account_number"],
                dest["account_number"], dest["id"], src_balance - amount)
        _record(conn, dest["id"], amount, description, source["account_number"],
                source["account_number"], source["id"], dest_balance + amount)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return None


@bp.get("/transfer/quick")
@login_required
def transfer_quick():
    """Transfer via GET — method tampering exercise.

    VULN: http_method_tampering — on easy/medium a state-changing transfer can
    be triggered with a plain GET (image tag / link), bypassing the form.
    """
    policy = current_policy()
    if not policy.is_vulnerable("http_method_tampering"):
        abort(405)

    source = _account_row(request.args.get("account_id") or 0)
    dest = query("SELECT * FROM accounts WHERE account_number = ?",
                 (request.args.get("dest_account") or "",), one=True)
    try:
        amount = int(request.args.get("amount") or 0)
    except ValueError:
        amount = 0
    if not source or not dest or amount == 0:
        abort(400)

    error = _apply_transfer(source, dest, amount,
                            request.args.get("description") or "Transfer cepat")
    if error:
        abort(400, description=error)
    audit("transfer.quick", f"from={source['account_number']} to={dest['account_number']}")
    return redirect(url_for("transactions.history", account_id=source["id"]))


# ---------------------------------------------------------------------------
# History + filter
# ---------------------------------------------------------------------------
def _filtered_rows(account_id, q, start, end):
    """Build the history query. SQLi lives in the concatenation branch."""
    policy = current_policy()
    base = (
        "SELECT t.*, a.account_number FROM transactions t "
        "JOIN accounts a ON a.id = t.account_id WHERE 1=1"
    )
    params = []

    if account_id:
        base += " AND t.account_id = ?"
        params.append(account_id)

    if policy.is_vulnerable("sqli_transactions") and not policy.is_hard:
        # VULN: sqli_transactions — every filter value is concatenated straight
        # into the SQL string. Payloads:
        #   q=' OR '1'='1                       -> tautology, every row returns
        #   q=x%' OR 1=1) UNION SELECT ... --   -> read any table (incl. hashes)
        #   start=2024-01-01'                   -> syntax error (error-based probe)
        if q:
            base += (f" AND (t.description LIKE '%{q}%' "
                     f"OR t.counterparty_name LIKE '%{q}%' "
                     f"OR t.ref_no LIKE '%{q}%')")
        if start:
            base += f" AND t.created_at >= '{start}'"
        if end:
            base += f" AND t.created_at <= '{end} 23:59:59'"
    else:
        # Keyword search is always bound safely...
        if q:
            base += (" AND (t.description LIKE ? OR t.counterparty_name LIKE ? "
                     "OR t.ref_no LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like, like])
        if start:
            if policy.is_vulnerable("sqli_transactions"):
                # VULN: sqli_transactions (hard) — only the date range stays
                # injectable. Subtle, but error-based probing (a lone quote
                # returns 500) and time-based blind extraction still work:
                # start=2024-01-01' AND 1=(WITH RECURSIVE ...) AND '1'='1
                base += f" AND t.created_at >= '{start}'"
            else:
                # FIX: bound parameters for every user-controlled value.
                base += " AND t.created_at >= ?"
                params.append(f"{start} 00:00:00")
        if end:
            if policy.is_vulnerable("sqli_transactions"):
                base += f" AND t.created_at <= '{end} 23:59:59'"
            else:
                base += " AND t.created_at <= ?"
                params.append(f"{end} 23:59:59")

    base += " ORDER BY t.created_at DESC, t.id DESC"
    return get_db().execute(base, params).fetchall()


@bp.get("/transactions")
@login_required
def history():
    policy = current_policy()
    accounts = query("SELECT * FROM accounts WHERE user_id = ? ORDER BY id",
                     (g.user["id"],))

    account_id = request.args.get("account_id") or (accounts[0]["id"] if accounts else None)
    # VULN: idor_transactions — the account_id query parameter is never
    # validated against the current user's accounts. Any authenticated user can
    # view another user's transaction history, detail or receipt.
    if account_id and not policy.is_vulnerable("idor_transactions"):
        if not _owns(g.user["id"], _account_row(account_id)):
            abort(403)

    q = request.args.get("q", "").strip()
    start = request.args.get("start", "").strip()
    end = request.args.get("end", "").strip()
    page = request.args.get("page", 1, type=int)

    # Keep the reflected XSS parameter realistic: only the first 120 chars are
    # echoed back, exactly like a typical "you searched for ..." banner.
    reflected_q = q[:120]

    rows = _filtered_rows(account_id, q, start, end) if account_id else []
    page_data = paginate(rows, page, PAGE_SIZE)
    total_in = sum(r["amount"] for r in rows if r["direction"] == "IN")
    total_out = sum(r["amount"] for r in rows if r["direction"] == "OUT")

    return render_template(
        "transactions/history.html",
        accounts=accounts,
        account_id=account_id,
        rows=page_data["items"],
        page=page_data,
        q=q,
        reflected_q=reflected_q,
        start=start,
        end=end,
        total_in=total_in,
        total_out=total_out,
        total_count=len(rows),
        xss_reflected=policy.is_vulnerable("xss_reflected"),
        xss_stored=policy.is_vulnerable("xss_stored"),
    )


@bp.get("/transactions/export.csv")
@login_required
def export_csv():
    policy = current_policy()
    accounts = query("SELECT * FROM accounts WHERE user_id = ? ORDER BY id",
                     (g.user["id"],))
    account_id = request.args.get("account_id") or (accounts[0]["id"] if accounts else None)
    if account_id and not policy.is_vulnerable("idor_transactions"):
        if not _owns(g.user["id"], _account_row(account_id)):
            abort(403)

    rows = _filtered_rows(account_id, request.args.get("q", "").strip(),
                          request.args.get("start", "").strip(),
                          request.args.get("end", "").strip()) if account_id else []

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ref_no", "tanggal", "tipe", "arah", "nominal",
                     "nama_lawan", "rekening_lawan", "deskripsi", "status"])
    for row in rows:
        writer.writerow([
            row["ref_no"], row["created_at"], row["tx_type"], row["direction"],
            row["amount"], row["counterparty_name"], row["counterparty_account"],
            row["description"], row["status"],
        ])
    audit("transactions.export", f"account_id={account_id} rows={len(rows)}")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="mutasi-{datetime.now():%Y%m%d}.csv"'},
    )


# ---------------------------------------------------------------------------
# Detail + receipt
# ---------------------------------------------------------------------------
@bp.get("/transactions/<int:tx_id>")
@login_required
def detail(tx_id):
    policy = current_policy()
    tx = query(
        "SELECT t.*, a.account_number, a.user_id AS owner_id, a.label "
        "FROM transactions t JOIN accounts a ON a.id = t.account_id "
        "WHERE t.id = ?",
        (tx_id,),
        one=True,
    )
    if not tx:
        abort(404)

    # VULN: idor_transactions — no ownership check on easy/medium/hard.
    if not policy.is_vulnerable("idor_transactions") and \
            tx["owner_id"] != g.user["id"] and g.user.get("role") not in (
                "admin", "admin_cs", "admin_finance"):
        abort(403)

    related = None
    if tx["related_account_id"]:
        related = query("SELECT * FROM accounts WHERE id = ?",
                        (tx["related_account_id"],), one=True)
    account = _account_row(tx["account_id"])
    owner = query("SELECT * FROM users WHERE id = ?", (tx["owner_id"],), one=True)

    return render_template("transactions/detail.html", tx=tx, related=related,
                           account=account, owner=owner,
                           xss_stored=policy.is_vulnerable("xss_stored"))


@bp.get("/transactions/<int:tx_id>/receipt")
@login_required
def receipt(tx_id):
    policy = current_policy()
    tx = query(
        "SELECT t.*, a.account_number, a.user_id AS owner_id "
        "FROM transactions t JOIN accounts a ON a.id = t.account_id "
        "WHERE t.id = ?",
        (tx_id,),
        one=True,
    )
    if not tx:
        abort(404)
    if not policy.is_vulnerable("idor_transactions") and \
            tx["owner_id"] != g.user["id"] and g.user.get("role") not in (
                "admin", "admin_cs", "admin_finance"):
        abort(403)
    account = _account_row(tx["account_id"])
    owner = query("SELECT * FROM users WHERE id = ?", (tx["owner_id"],), one=True)
    return render_template("transactions/receipt.html", tx=tx,
                           account=account, owner=owner,
                           xss_stored=policy.is_vulnerable("xss_stored"))
