"""Stage 8 smoke test — public marketing pages across every lab level.

Covers the pages themselves (products, calculator, news, contact, FAQ) plus the
training holes they introduce: SQLi in news search, reflected XSS in the news
banner and the contact form, parameter tampering in the installment
calculator, and CSRF on the public form.
"""

import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from urllib.parse import quote

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

SRC_DB = os.path.join(ROOT, "db", "nusabank.db")

PAGES = ["/", "/produk", "/kalkulator", "/berita", "/faq", "/kontak",
         "/berita/promo-tabungan-nusa-prima"]

CALC_BASE = {"produk": "kendaraan", "harga": "150000000",
             "dp": "30000000", "tenor": "36", "form_version": "v2"}


def make_client(level, tmpdir):
    db_copy = os.path.join(tmpdir, f"nusabank-{level}.db")
    shutil.copyfile(SRC_DB, db_copy)
    uploads = os.path.join(tmpdir, f"uploads-{level}")
    shutil.copytree(os.path.join(ROOT, "uploads"), uploads, dirs_exist_ok=True)
    os.environ.update(LAB_LEVEL=level, NUSABANK_DB=db_copy,
                      NUSABANK_UPLOADS=uploads, NUSABANK_COOKIE_SECURE="0")
    from app import create_app

    app = create_app({"DB_PATH": db_copy, "UPLOAD_DIR": uploads})
    return app, db_copy


def csrf(client, path="/kontak"):
    body = client.get(path).data.decode("utf-8", "replace")
    m = re.search(r'name="csrf_token" value="([^"]+)"', body)
    return m.group(1) if m else "nusabank-csrf-static-token"


def article_links(resp):
    return resp.data.decode("utf-8", "replace").count('class="article-card"')


def rows(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def calc(client, extra=None, token=None):
    data = dict(CALC_BASE)
    data.update(extra or {})
    data.setdefault("csrf_token", token or "nusabank-csrf-static-token")
    return client.post("/kalkulator", data=data)


def run(level):
    tmpdir = tempfile.mkdtemp(prefix=f"stage8-{level}-")
    app, db_path = make_client(level, tmpdir)
    client = app.test_client()
    out = {"level": level}

    # --- 1) Every public page renders ------------------------------------
    out["pages"] = {p: client.get(p).status_code for p in PAGES}

    # --- 2) Products page pulls its rates from settings ------------------
    body = client.get("/produk").data.decode("utf-8", "replace")
    out["products_rate"] = "4.25% p.a." in body or "4,25% p.a." in body
    out["products_rows"] = body.count('class="product-row ')

    # --- 3) News SQLi ------------------------------------------------------
    baseline = article_links(client.get("/berita?q=zzzzz"))
    payload = "zzzzz' OR 1=1 OR '"
    injected = article_links(client.get("/berita?q=" + quote(payload)))
    out["news_baseline"] = baseline
    out["news_injected"] = injected
    out["news_sqli"] = injected > baseline

    # --- 4) Reflected XSS in the news search banner ------------------------
    xss = "<script>alert(1)</script>"
    body = client.get("/berita?q=" + quote(xss)).data.decode("utf-8", "replace")
    banner = re.search(r"Hasil pencarian untuk:\s*(.*?)</div>", body, re.S)
    out["news_xss_raw"] = bool(banner) and xss in banner.group(1)
    out["news_xss_escaped"] = bool(banner) and "&lt;script&gt;" in banner.group(1)

    # --- 5) Reflected XSS in the contact thank-you banner ------------------
    token = csrf(client)
    payload_name = "<img src=x onerror=alert(1)>"
    r = client.post("/kontak", data={
        "csrf_token": token, "name": payload_name, "email": "attacker@example.com",
        "phone": "081200000000", "subject": "Tes XSS",
        "message": "Pesan uji coba yang cukup panjang.",
    })
    body = r.data.decode("utf-8", "replace")
    out["contact_status"] = r.status_code
    banner = re.search(r'notice notice--success">\s*(.*?)</div>', body, re.S)
    out["contact_xss_raw"] = bool(banner) and payload_name in banner.group(1)
    out["contact_xss_escaped"] = bool(banner) and "&lt;img src=x" in banner.group(1)

    stored = rows(db_path, "SELECT COUNT(*) AS c FROM contacts "
                           "WHERE email = 'attacker@example.com'")
    out["contact_saved"] = stored[0]["c"] == 1

    # --- 6) CSRF on the public contact form --------------------------------
    r = client.post("/kontak", data={
        "name": "Tanpa Token", "email": "csrf@example.com",
        "message": "Pesan tanpa token CSRF sama sekali.",
    })
    out["contact_no_csrf_status"] = r.status_code

    # --- 7) Calculator parameter tampering ---------------------------------
    # Baseline: the honest form (server rate, nothing weird).
    honest = calc(client)
    honest_body = honest.data.decode("utf-8", "replace")
    m = re.search(r'class="balance-xl">([^<]+)<', honest_body)
    out["calc_honest"] = m.group(1).strip() if m else None

    # easy: the hidden `rate` field is trusted -> rate=0 kills the interest.
    zero = calc(client, {"rate": "0"})
    m = re.search(r'class="balance-xl">([^<]+)<', zero.data.decode("utf-8", "replace"))
    zero_installment = m.group(1).strip() if m else None
    out["calc_rate_0"] = zero_installment
    out["calc_rate_tamper"] = bool(zero_installment) and zero_installment != out["calc_honest"]

    # medium/hard: dp larger than the price -> negative principal accepted.
    def calc_outcome(resp):
        """Return ('result', installment) or ('error', message) or (None, None)."""
        html = resp.data.decode("utf-8", "replace")
        m = re.search(r'class="balance-xl">([^<]+)<', html)
        if m:
            return "result", m.group(1).strip()
        m = re.search(r'notice notice--danger">\s*([^<]+)', html)
        if m:
            return "error", m.group(1).strip()
        return None, None

    state, value = calc_outcome(calc(client, {"dp": "200000000", "harga": "150000000"}))
    out["calc_neg_dp"] = {"state": state, "value": value}
    out["calc_neg_dp_accepted"] = state == "result" and value.startswith("-Rp")

    # hard-only: the validation gate keys off a client field.
    state, value = calc_outcome(calc(client, {"dp": "200000000", "harga": "150000000",
                                              "form_version": ""}))
    out["calc_hard_gate"] = {"state": state, "value": value}
    out["calc_hard_gate_bypass"] = state == "result" and value.startswith("-Rp")

    # patched: negative tenor is rejected outright.
    state, value = calc_outcome(calc(client, {"tenor": "-12"}))
    out["calc_neg_tenor_rejected"] = state == "error"

    # --- 8) News detail increments the view counter ------------------------
    before = rows(db_path, "SELECT views FROM news WHERE slug = 'dukungan-umkm'")[0]["views"]
    client.get("/berita/dukungan-umkm")
    after = rows(db_path, "SELECT views FROM news WHERE slug = 'dukungan-umkm'")[0]["views"]
    out["views_incremented"] = after == before + 1

    # --- 9) Unknown article -> 404 ----------------------------------------
    out["news_404"] = client.get("/berita/tidak-ada-artikel-ini").status_code

    # --- 10) DOM XSS sink is wired up --------------------------------------
    index_body = client.get("/").data.decode("utf-8", "replace")
    js_body = client.get("/static/js/app.js").data.decode("utf-8", "replace")
    out["dom_sink_element"] = 'id="dom-greeting"' in index_body
    out["dom_sink_js"] = "innerHTML" in js_body
    out["dom_sink_guard"] = "textContent" in js_body

    return out


def main():
    results = {}
    for level in ("easy", "medium", "hard", "patched"):
        try:
            results[level] = run(level)
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            results[level] = {"level": level, "error": repr(exc)}

    print("\n=== SUMMARY ===")
    for level, data in results.items():
        print(level, "->", json.dumps(
            {k: v for k, v in data.items() if k not in ("level",)},
            ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
