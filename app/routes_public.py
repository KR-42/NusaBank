"""Public routes: marketing pages, information-disclosure surfaces, calculator.

The pages in this module are the ones a visitor sees before signing in, plus
the fake internal endpoints that serve as training targets (robots.txt, debug,
backup archive, cloud-metadata simulation).
"""

import io
import zipfile

from flask import (Blueprint, Response, abort, current_app, jsonify,
                   render_template, request)

from .db import execute, get_setting, query
from .lab import current_policy
from .security import csrf_verify
from .utils import paginate

bp = Blueprint("public", __name__)

PRODUCTS = {
    "tabungan": {"name": "Tabungan Nusa Prima", "rate": "2,50% p.a."},
    "deposito": {"name": "Deposito Berjangka", "rate": "4,25% p.a."},
    "kartu-kredit": {"name": "NusaCard Platinum", "rate": "Cashback 5%"},
    "asuransi-jiwa": {"name": "Asuransi Jiwa Nusa Proteksi", "rate": "Premi Rp 50.000"},
    "asuransi-kendaraan": {"name": "Asuransi Kendaraan NusaDrive", "rate": "Premi Rp 150.000"},
}

# Longer copy shown on /produk. Kept apart from PRODUCTS so the landing page
# keeps its compact card layout.
PRODUCT_DETAILS = {
    "tabungan": {
        "tagline": "Rekening harian tanpa biaya administrasi untuk kebutuhan sehari-hari.",
        "features": [
            "Bebas biaya administrasi bulanan",
            "Transfer antar bank real-time 24/7",
            "Kartu debit NusaCard dengan NFC",
            "Setoran awal mulai Rp 50.000",
        ],
        "meta": "Dijamin LPS hingga Rp 2 miliar (simulasi).",
        "cta": "register",
    },
    "deposito": {
        "tagline": "Simpanan berjangka dengan bunga tetap dan jangka waktu fleksibel.",
        "features": [
            "Tenor 1, 3, 6, dan 12 bulan",
            "Bunga tetap dibayar di muka atau saat jatuh tempo",
            "Pencairan otomatis ke rekening tabungan",
            "Setoran awal mulai Rp 1.000.000",
        ],
        "meta": "Suku bunga mengikuti pengumuman resmi bank (simulasi).",
        "cta": "login",
    },
    "kartu-kredit": {
        "tagline": "Kartu kredit dengan cashback untuk setiap transaksi ritel.",
        "features": [
            "Cashback 5% untuk kategori ritel",
            "Cicilan 0% hingga 12 bulan",
            "Tanpa biaya tahunan pada tahun pertama",
            "Limit hingga Rp 100.000.000",
        ],
        "meta": "Persetujuan mengikuti hasil analisis kredit (simulasi).",
        "cta": "login",
    },
    "asuransi-jiwa": {
        "tagline": "Perlindungan jiwa untuk keluarga dengan premi terjangkau.",
        "features": [
            "Uang pertanggungan hingga Rp 1 miliar",
            "Premi mulai Rp 50.000 per bulan",
            "Pengajuan klaim langsung dari aplikasi",
            "Tanpa pemeriksaan medis untuk limit tertentu",
        ],
        "meta": "Dikelola bersama mitra reasuransi (simulasi).",
        "cta": "login",
    },
    "asuransi-kendaraan": {
        "tagline": "Perlindungan kendaraan all-risk dengan layanan derek 24 jam.",
        "features": [
            "Perlindungan all-risk dan TLO",
            "Layanan derek dan bantuan darurat",
            "Bengkel rekanan di 40 kota",
            "Premi mulai Rp 150.000 per bulan",
        ],
        "meta": "Premi dipengaruhi jenis kendaraan dan wilayah (simulasi).",
        "cta": "login",
    },
}

# Financing products offered by the installment calculator. `rate` is the
# reference interest rate the server is supposed to use (percent per annum).
FINANCING = {
    "kendaraan": {"label": "Kredit Kendaraan NusaDrive", "rate": 8.5, "max_tenor": 60},
    "multiguna": {"label": "Kredit Multiguna", "rate": 10.0, "max_tenor": 84},
    "kpr": {"label": "KPR Nusa Griya", "rate": 7.25, "max_tenor": 240},
}

DEFAULT_CALC = {"produk": "kendaraan", "harga": "150000000",
                "dp": "30000000", "tenor": "36"}


# ---------------------------------------------------------------------------
# Landing & marketing pages
# ---------------------------------------------------------------------------
@bp.get("/")
def index():
    return render_template("public/index.html", products=PRODUCTS)


@bp.get("/produk")
def products():
    return render_template(
        "public/products.html",
        products=PRODUCTS,
        details=PRODUCT_DETAILS,
        deposit_rate=get_setting("deposit_rate", "4.25"),
        loan_rate=get_setting("loan_rate", "8.5"),
        financing=FINANCING,
    )


def _validate_financing(price, dp, tenor, product):
    """Server-side sanity checks used on the hardened levels."""
    if price <= 0:
        return "Harga barang harus lebih besar dari nol."
    if dp < 0 or dp >= price:
        return "Uang muka harus di antara Rp 0 dan harga barang."
    if tenor < 1 or tenor > product["max_tenor"]:
        return f"Tenor harus antara 1 dan {product['max_tenor']} bulan."
    return None


def _financing_result(price, dp, tenor, rate):
    """Flat-interest simulation used by the calculator."""
    principal = price - dp
    interest = principal * (rate / 100.0) * (tenor / 12.0)
    total = principal + interest
    installment = total / tenor if tenor else total
    return {
        "principal": int(round(principal)),
        "interest": int(round(interest)),
        "total": int(round(total)),
        "installment": int(round(installment)),
        "tenor": tenor,
        "rate": rate,
    }


@bp.route("/kalkulator", methods=["GET", "POST"])
def calculator():
    """Installment simulator.

    easy   : the interest rate is taken from the request, so it can be set to 0
             or a negative number.
    medium : the rate is recomputed server-side, but the down payment and the
             tenor are used as submitted (dp > price gives a negative
             principal, a negative tenor subtracts interest).
    hard   : full validation, but it only runs when the hidden `form_version`
             field equals "v2" — a client-controlled flag.
    patched: validation always runs.
    """
    policy = current_policy()
    form = dict(DEFAULT_CALC)
    result = None
    error = None

    if request.method == "GET" and request.args.get("produk") in FINANCING:
        form["produk"] = request.args["produk"]

    if request.method == "POST":
        form = {
            "produk": request.form.get("produk", "kendaraan"),
            "harga": request.form.get("harga", ""),
            "dp": request.form.get("dp", ""),
            "tenor": request.form.get("tenor", ""),
        }
        if form["produk"] not in FINANCING:
            form["produk"] = "kendaraan"
        product = FINANCING[form["produk"]]
        server_rate = float(product["rate"])

        try:
            price = int(float(form["harga"] or 0))
            dp = int(float(form["dp"] or 0))
            tenor = int(float(form["tenor"] or 0))
        except ValueError:
            price = dp = tenor = 0
            error = "Masukkan angka yang valid pada harga, uang muka, dan tenor."

        rate = server_rate
        if not error:
            if policy.is_vulnerable("calc_parameter_tampering"):
                if policy.is_easy:
                    # VULN: calc_parameter_tampering — the hidden `rate` field
                    # is trusted. Payload: rate=-50 (a "discount" quote) or
                    # rate=0 (no interest at all).
                    try:
                        rate = float(request.form.get("rate") or server_rate)
                    except ValueError:
                        rate = server_rate
                elif policy.is_hard:
                    # VULN: calc_parameter_tampering — validation is skipped
                    # unless the client sends form_version=v2. Payload: omit
                    # the field and send dp=200000000&tenor=-12.
                    if request.form.get("form_version") == "v2":
                        error = _validate_financing(price, dp, tenor, product)
                # medium falls through with no checks beyond the server rate.
            else:
                # FIX: every value is re-derived or validated on the server.
                error = _validate_financing(price, dp, tenor, product)

        if not error:
            result = _financing_result(price, dp, tenor, rate)

    return render_template(
        "public/calculator.html",
        form=form,
        financing=FINANCING,
        result=result,
        error=error,
    )


@bp.get("/berita")
def news():
    """News listing with keyword search.

    The keyword is concatenated into the query on easy/medium and, through a
    keyword blacklist, still on hard. Only `patched` binds it.
    """
    policy = current_policy()
    q = request.args.get("q", "").strip()
    category = request.args.get("kategori", "").strip()
    page = request.args.get("page", 1, type=int)
    reflected_q = q[:120]

    base = ("SELECT id, slug, title, category, excerpt, author, views, published_at "
            "FROM news WHERE is_published = 1")
    order = " ORDER BY published_at DESC"

    if not q:
        rows = query(base + order)
    elif policy.is_vulnerable("sqli_search"):
        if policy.is_hard:
            # VULN: sqli_search (hard) — a case-sensitive blacklist of the
            # usual keywords. `' OR 1=1 OR '` slips through and returns every
            # article, which is enough to confirm the injection.
            blocked = ("UNION", "--", "/*", ";")
            if any(token in q for token in blocked):
                rows = []
            else:
                rows = query(base + f" AND (title LIKE '%{q}%' OR excerpt LIKE '%{q}%'"
                                    f" OR body LIKE '%{q}%')" + order)
        else:
            # VULN: sqli_search — concatenated LIKE clause.
            #   q=' OR 1=1 OR '                 -> every published article
            #   q=x%' UNION SELECT ... --       -> read other tables
            rows = query(base + f" AND (title LIKE '%{q}%' OR excerpt LIKE '%{q}%'"
                                f" OR body LIKE '%{q}%')" + order)
    else:
        # FIX: bound parameters.
        like = f"%{q}%"
        rows = query(base + " AND (title LIKE ? OR excerpt LIKE ? OR body LIKE ?)" + order,
                     (like, like, like))

    categories = query("SELECT DISTINCT category FROM news WHERE is_published = 1 "
                       "ORDER BY category")
    if category:
        rows = [r for r in rows if r["category"] == category]

    # Keep an out-of-range page number from producing an empty listing.
    last_page = max((len(rows) + 5) // 6, 1)
    page = min(max(page, 1), last_page)

    return render_template(
        "public/news.html",
        page_data=paginate(rows, page, 6),
        q=q,
        reflected_q=reflected_q,
        category=category,
        categories=[r["category"] for r in categories],
        xss_reflected=policy.is_vulnerable("xss_reflected"),
    )


@bp.get("/berita/<slug>")
def news_detail(slug):
    article = query("SELECT * FROM news WHERE slug = ? AND is_published = 1",
                    (slug,), one=True)
    if not article:
        abort(404)
    execute("UPDATE news SET views = views + 1 WHERE id = ?", (article["id"],))
    others = query("SELECT slug, title, category, published_at FROM news "
                   "WHERE is_published = 1 AND id != ? ORDER BY published_at DESC LIMIT 3",
                   (article["id"],))
    paragraphs = [p.strip() for p in (article["body"] or "").split("\n\n") if p.strip()]
    return render_template("public/news_detail.html", article=article,
                           paragraphs=paragraphs, others=others)


@bp.route("/kontak", methods=["GET", "POST"])
def contact():
    policy = current_policy()
    thanks = None
    errors = []
    form = {"name": "", "email": "", "phone": "", "subject": "", "message": ""}

    if request.method == "POST":
        csrf_verify()
        form = {key: (request.form.get(key) or "").strip()[:500]
                for key in form}
        if not form["name"]:
            errors.append("Nama wajib diisi.")
        if not form["email"] or "@" not in form["email"]:
            errors.append("Alamat email tidak valid.")
        if len(form["message"]) < 10:
            errors.append("Pesan minimal 10 karakter.")

        if not errors:
            execute(
                "INSERT INTO contacts(name, email, phone, subject, message) "
                "VALUES(?,?,?,?,?)",
                (form["name"], form["email"], form["phone"],
                 form["subject"] or "Pertanyaan umum", form["message"]),
            )
            # VULN: xss_reflected — the visitor's name is echoed into the thank
            # you banner without escaping. Payload in the name field:
            #   <img src=x onerror=alert(document.cookie)>
            thanks = f"Terima kasih, {form['name']}. Pesan Anda sudah kami terima."
            form = {key: "" for key in form}  # clear the form after success

    return render_template(
        "public/contact.html",
        form=form,
        errors=errors,
        thanks=thanks,
        xss_reflected=policy.is_vulnerable("xss_reflected"),
        support_email=get_setting("support_email", "care@nusabank.example.com"),
    )


@bp.get("/faq")
def faq():
    return render_template("public/faq.html")


# ---------------------------------------------------------------------------
# Infrastructure / information disclosure surfaces
# ---------------------------------------------------------------------------
@bp.get("/health")
def health():
    return jsonify(status="ok", service="nusabank", level=current_policy().level)


@bp.get("/robots.txt")
def robots():
    policy = current_policy()
    if policy.is_vulnerable("sensitive_robots"):
        # VULN: sensitive_robots — internal paths disclosed to crawlers.
        body = (
            "User-agent: *\n"
            "Disallow: /admin\n"
            "Disallow: /admin/login\n"
            "Disallow: /api/v1/\n"
            "Disallow: /debug\n"
            "Disallow: /backup.zip\n"
            "Disallow: /uploads/\n"
            "Disallow: /.git/\n"
        )
    else:
        body = "User-agent: *\nDisallow: /admin\nDisallow: /api/\n"
    return Response(body, mimetype="text/plain")


@bp.get("/.git/config")
def fake_git_config():
    if current_policy().is_patched("exposed_backup"):
        abort(404)
    # VULN: exposed_backup — fake repo metadata left in the web root.
    body = (
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
        "\tbare = false\n[remote \"origin\"]\n"
        "\turl = https://git.internal.nusabank.lab/nusabank/core.git\n"
        "[user]\n\tname = deploy\n\temail = deploy@nusabank.lab\n"
    )
    return Response(body, mimetype="text/plain")


@bp.get("/backup.zip")
def fake_backup():
    if current_policy().is_patched("exposed_backup"):
        abort(404)
    # VULN: exposed_backup — fake archive containing lab credentials.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "backup/env.txt",
            "DB_USER=nusabank\nDB_PASS=NusaBank!2024\n"
            "SMTP_PASS=mail-lab-pass\nFLAG=FLAG{backup_archive_leaked}\n",
        )
        zf.writestr("backup/README.txt", "Backup harian NusaBank. Hapus dari web root!\n")
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": "attachment; filename=backup.zip"})


@bp.get("/debug")
def debug():
    if current_policy().is_patched("debug_endpoint"):
        abort(404)
    # VULN: debug_endpoint — environment and configuration disclosure.
    import os
    import platform
    import sys
    return render_template(
        "public/debug.html",
        env={k: v for k, v in os.environ.items() if "SECRET" not in k},
        python_version=sys.version.replace("\n", " "),
        platform=platform.platform(),
        cwd=os.getcwd(),
        debug=os.name,
        config={k: repr(v) for k, v in current_app.config.items()},
        db_path=current_app.config["DB_PATH"],
        upload_dir=current_app.config["UPLOAD_DIR"],
    )


@bp.get("/internal/metadata")
def internal_metadata():
    """Fake cloud metadata endpoint — the SSRF exercise target (stage 6)."""
    return jsonify(
        service="nusabank-internal-metadata",
        environment="lab",
        hostname="nusabank-web",
        iam_role="arn:aws:iam::000000000000:role/nusabank-lab",
        access_key="AKIAFAKEFAKEFAKE0000",
        secret_key="fake/secret/for/lab/only",
        internal_api="http://127.0.0.1:8080/internal/admin-api",
        flag="FLAG{ssrf_internal_metadata_reached}",
    )


@bp.get("/internal/admin-api")
def internal_admin_api():
    try:
        user_count = query("SELECT COUNT(*) AS c FROM users", one=True)["c"]
    except Exception:
        user_count = 0
    return jsonify(
        service="nusabank-internal-admin",
        message="Internal admin API (simulated)",
        users=user_count,
        flag="FLAG{internal_admin_api_exposed}",
    )
