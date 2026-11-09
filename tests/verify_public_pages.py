"""Public pages: marketing site, news, contact form and installment calculator.

Covers the pages themselves plus the training flaws they expose: SQL injection
and reflected XSS in the news search, reflected XSS and missing CSRF on the
contact form, parameter tampering in the calculator, and the DOM sink on the
home page.
"""

import re
import sys
from urllib.parse import quote

from harness import csrf, lab, parse_levels, rows, run_module, text

TITLE = "public pages - news SQLi/XSS, contact form, calculator"

PAGES = ["/", "/produk", "/kalkulator", "/berita", "/faq", "/kontak",
         "/berita/promo-tabungan-nusa-prima"]

CALC_FORM = {"produk": "kendaraan", "harga": "150000000",
             "dp": "30000000", "tenor": "36", "form_version": "v2"}

EXPECT = {
    "pages_all_200":            (True, True, True, True),
    "products_rates_rendered":  (True, True, True, True),
    "products_rows":            (5, 5, 5, 5),
    # news search: SQLi and reflected XSS
    "news_sqli":                (True, True, True, False),
    "news_xss_raw":             (True, True, True, False),
    # contact form: reflected XSS, storage, and CSRF protection
    "contact_status":           (200, 200, 200, 200),
    "contact_xss_raw":          (True, True, True, False),
    "contact_saved":            (True, True, True, True),
    "contact_without_csrf":     (200, 200, 400, 400),
    # calculator: view source and parameter tampering
    "calc_honest_installment":  ("Rp 4.183.333",) * 4,
    "calc_rate_tamper":         (True, False, False, False),
    "calc_negative_principal":  (True, True, False, False),
    "calc_gate_bypass":         (True, True, True, False),
    "calc_negative_tenor":      (False, False, True, True),
    # misc public behaviour
    "news_views_incremented":   (True, True, True, True),
    "news_unknown_404":         (404, 404, 404, 404),
    "dom_sink_present":         (True, True, True, True),
}


def _article_links(resp):
    return text(resp).count('class="article-card"')


def _calc_outcome(resp):
    """Return ('result', installment) | ('error', message) | (None, None)."""
    body = text(resp)
    match = re.search(r'class="balance-xl">([^<]+)<', body)
    if match:
        return "result", match.group(1).strip()
    match = re.search(r'notice notice--danger">\s*([^<]+)', body)
    if match:
        return "error", match.group(1).strip()
    return None, None


def run(level):
    out = {}
    with lab(level) as (app, db_path, _uploads, _tmp):
        client = app.test_client()

        # --- 1) every public page renders --------------------------------
        out["pages_all_200"] = all(
            client.get(page).status_code == 200 for page in PAGES)

        # --- 2) products page reads its rates from settings --------------
        products = text(client.get("/produk"))
        out["products_rates_rendered"] = "4.25% p.a." in products \
            or "4,25% p.a." in products
        out["products_rows"] = products.count('class="product-row ')

        # --- 3) news search: SQLi ----------------------------------------
        baseline = _article_links(client.get("/berita?q=zzzzz"))
        injected = _article_links(client.get("/berita?q=" + quote("zzzzz' OR 1=1 OR '")))
        out["news_sqli"] = injected > baseline

        # --- 4) news search: reflected XSS -------------------------------
        xss = "<script>alert(1)</script>"
        body = text(client.get("/berita?q=" + quote(xss)))
        banner = re.search(r"Hasil pencarian untuk:\s*(.*?)</div>", body, re.S)
        out["news_xss_raw"] = bool(banner) and xss in banner.group(1)

        # --- 5) contact form: reflected XSS + storage ---------------------
        token = csrf(client, "/kontak")
        payload = "<img src=x onerror=alert(1)>"
        resp = client.post("/kontak", data={
            "csrf_token": token, "name": payload, "email": "attacker@example.com",
            "phone": "081200000000", "subject": "Tes XSS",
            "message": "Pesan uji coba yang cukup panjang."})
        out["contact_status"] = resp.status_code
        banner = re.search(r'notice notice--success">\s*(.*?)</div>', text(resp), re.S)
        out["contact_xss_raw"] = bool(banner) and payload in banner.group(1)
        out["contact_saved"] = rows(
            db_path, "SELECT COUNT(*) AS c FROM contacts WHERE email='attacker@example.com'"
        )[0]["c"] == 1

        # --- 6) contact form: no CSRF token ------------------------------
        out["contact_without_csrf"] = client.post("/kontak", data={
            "name": "Tanpa Token", "email": "csrf@example.com",
            "message": "Pesan tanpa token CSRF sama sekali."}).status_code

        # --- 7) calculator ------------------------------------------------
        def calc(**overrides):
            data = {**CALC_FORM, **overrides,
                    "csrf_token": "nusabank-csrf-static-token"}
            return client.post("/kalkulator", data=data)

        state, value = _calc_outcome(calc())
        out["calc_honest_installment"] = value if state == "result" else None

        state, value = _calc_outcome(calc(rate="0"))
        out["calc_rate_tamper"] = state == "result" and \
            value != out["calc_honest_installment"]

        # down payment above the price leaves a negative principal
        state, _value = _calc_outcome(calc(dp="200000000", harga="150000000"))
        out["calc_negative_principal"] = state == "result"

        # the validation gate keys off a client-supplied field on hard
        state, _value = _calc_outcome(calc(dp="200000000", harga="150000000",
                                           form_version=""))
        out["calc_gate_bypass"] = state == "result"

        state, _value = _calc_outcome(calc(tenor="-12"))
        out["calc_negative_tenor"] = state == "error"

        # --- 8) news view counter and 404 --------------------------------
        before = rows(db_path, "SELECT views FROM news WHERE slug='dukungan-umkm'")[0]["views"]
        client.get("/berita/dukungan-umkm")
        out["news_views_incremented"] = rows(
            db_path, "SELECT views FROM news WHERE slug='dukungan-umkm'"
        )[0]["views"] == before + 1
        out["news_unknown_404"] = client.get("/berita/tidak-ada-artikel-ini").status_code

        # --- 9) the DOM sink is wired up ---------------------------------
        out["dom_sink_present"] = 'id="dom-greeting"' in text(client.get("/")) \
            and "innerHTML" in text(client.get("/static/js/app.js"))
    return out


if __name__ == "__main__":
    sys.exit(run_module(TITLE, run, EXPECT, parse_levels()))
