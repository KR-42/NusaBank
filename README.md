<div align="center">

# 🏦 NusaBank

### A digital bank, built to be broken.

A full-stack, deliberately vulnerable **banking web application** for hands-on
penetration-testing practice. Realistic flows, real bugs, four difficulty levels,
and a secure reference implementation you can diff against line by line.

<br>

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0.3-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)

<br>

![Levels](https://img.shields.io/badge/difficulty-easy%20%7C%20medium%20%7C%20hard%20%7C%20patched-0b3d91?style=flat-square)
![Flags](https://img.shields.io/badge/feature%20flags-48-cc0000?style=flat-square)
![Routes](https://img.shields.io/badge/http%20routes-77-555?style=flat-square)
![Seed](https://img.shields.io/badge/seed%20data-1%2C161%20transactions-2ea44f?style=flat-square)
![Bound](https://img.shields.io/badge/network-127.0.0.1%3A8080%20only-critical?style=flat-square)

</div>

---

> [!WARNING]
> **This application is intentionally vulnerable. Never expose it to the internet.**
> Run it only on your own machine or an isolated VM. All data is fictional — there
> are no real customers, accounts, or credentials anywhere in this repository.

---

## ✨ Why NusaBank?

Most security labs stop at "a login form with SQL injection". NusaBank is built as a
**complete product** instead: a public site, customer authentication, a dashboard,
PIN-protected transfers, transaction history with CSV export, KYC uploads, insurance
claims, support tickets, an e-wallet webhook, a JWT-protected REST API, and a
back-office admin panel. The bugs therefore live where they would in a real product —
not on demo pages bolted on for the exercise.

| | |
|---|---|
| 🎯 **48 centrally managed feature flags** | One matrix in `app/lab.py` decides how every feature behaves at every level. No scattered `if debug:` branches. |
| 🔀 **Four levels, not two** | `easy` → everything open. `medium` → defences you can bypass. `hard` → one subtle flaw per module. `patched` → the secure reference. |
| 🧭 **Annotated source** | Every vulnerable branch is marked `# VULN: <name>`, its secure twin `# FIX:` — grep them and compare side by side. |
| 🧪 **Verification suite** | Five modules in `tests/` assert the expected behaviour of every level, so regressions fail loudly instead of silently. |
| 🚢 **Hardened container** | Non-root, `read_only`, `cap_drop: ALL`, `no-new-privileges`, published only to `127.0.0.1:8080`. |
| 📚 **Complete documentation** | A vulnerability catalogue, a step-by-step walkthrough, and a credentials/flag reference. |

---

## 🚀 Quick Start

### Docker (recommended)

```bash
git clone https://github.com/KR-42/NusaBank.git && cd NusaBank

# Default level: medium
docker compose up --build

# Open http://127.0.0.1:8080
```

Switch levels without rebuilding:

```bash
LAB_LEVEL=easy    docker compose up --force-recreate
LAB_LEVEL=hard    docker compose up --force-recreate
LAB_LEVEL=patched docker compose up --force-recreate
```

Reset the database to its seeded state:

```bash
docker compose down && rm -f db/nusabank.db && docker compose up --build
```

### Without Docker (development)

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python db/seed.py            # seed initial data (only when the DB is empty)
LAB_LEVEL=easy python -m app --host=127.0.0.1:8080
```

> The server always binds explicitly to `127.0.0.1` when run on the host. Only
> inside the container does it listen on `0.0.0.0` — and even then Compose publishes
> that port to loopback alone.

---

## 🎚️ The Four Training Levels

The level comes from the `LAB_LEVEL` environment variable, is re-evaluated on every
request, and is printed in the site footer — so you always know which mode is live.

| Level | Active flaws | Best for | Character |
|---|---:|---|---|
| 🟢 **easy** | **45 / 48** | Beginners, classroom demos | Every defence is off. Every flaw is directly exploitable. |
| 🟡 **medium** | **45 / 48** | Bypass practice | Blacklists, client-side validation, and naive filters that can be defeated. |
| 🔴 **hard** | **15 / 48** | Practical exams | Real defences; one subtle defect per module remains. |
| 🔒 **patched** | **0** | Reference & remediation | The secure implementation. Every documented payload must fail. |

<details>
<summary><b>See the flaws intentionally left open at the <code>hard</code> level</b></summary>

<br>

| Module | Flaw | Key payload |
|---|---|---|
| Public & admin search | `sqli_search` | `zzzz' OR 1=1 OR '` — the blacklist is case-sensitive |
| Transaction history | `sqli_transactions` | Injection through `start` (error-based and time-based) |
| Loan calculator | `calc_parameter_tampering` | Drop the `form_version=v2` marker |
| Transfers | `negative_transfer` | `amount=-10000000` |
| Insurance claims | `claim_cumulative_bypass` | Several claims that each pass on their own |
| Profile & admin | `mass_assignment` | `role_id=2` |
| Back office | `admin_role_separation` | `cs123` approves claims and edits settings |
| Redirects | `open_redirect` | `?next=//evil.example` |
| Discovery | `sensitive_robots` | `robots.txt` leaks internal paths |
| XSS | `xss_reflected`, `xss_stored`, `xss_dom` | Three different contexts |
| Authorization | `idor_transactions`, `idor_profile` | ID enumeration |
| Tickets & claims | `internal_note_exposure` | Agent notes shown to customers |

</details>

---

## 🧩 Attack Surface

<details open>
<summary><b>Injection</b> — SQLi (login, search, filters, admin panel), command injection, XXE*, insecure deserialization*</summary>

SQL injection appears in four distinct shapes: authentication, free-text search,
date filters (including blind time-based extraction), and back-office search.
Command injection lives in the network diagnostics tool, with a blacklist-bypass
challenge on `medium`.
*`xxe_import` and `insecure_deserialization` are recorded in the matrix as design
intent; see the coverage note in `docs/WALKTHROUGH.md` §15.*

</details>

<details>
<summary><b>Broken Access Control</b> — IDOR, privilege escalation, mass assignment, path traversal, CSRF, open redirect</summary>

IDOR covers transactions, receipts, KYC documents, claims, tickets, and profiles via
the API. Privilege escalation comes from two directions: a customer who can open
`/admin`, and back-office accounts that are not restricted per role. Path traversal
is reachable through `/uploads/<path>` and `/admin/files?name=`.

</details>

<details>
<summary><b>XSS</b> — reflected, stored, and DOM-based</summary>

Reflected in news search, transaction search, and a contact form that needs no login.
Stored in transfer descriptions and support tickets (which also execute in the CS
back office). DOM-based through `location.hash` on the home-page hero.

</details>

<details>
<summary><b>Authentication & Sessions</b> — weak hashing, enumeration, brute force, reset tokens, fixation, remember-me</summary>

Unsalted MD5, a password policy that accepts a single character, error messages that
distinguish valid from invalid users, no account lockout, reset tokens shaped
`<id>-<date>`, sessions that are never rotated, and a remember-me cookie containing
the raw user ID.

</details>

<details>
<summary><b>Business Logic</b> — negative balances, race conditions, PIN bypass, excessive claims</summary>

A negative transfer amount grows the sender's balance. Six to ten parallel requests
read the same balance before committing (double spend). The PIN field can be omitted
entirely. Insurance claims accept negative amounts or values above the coverage — and
on `hard`, several small claims can break the limit cumulatively.

</details>

<details>
<summary><b>Infrastructure & API</b> — SSRF, JWT, CORS, rate limiting, security headers</summary>

The e-wallet webhook fetches any URL a customer supplies (SSRF into internal
endpoints). A weak-secret JWT accepts `alg: none` tokens. CORS reflects any origin
with `Allow-Credentials: true`. The rate limiter can be bypassed with
`X-Forwarded-For`. Cookies lack `HttpOnly`/`SameSite`, security headers are empty,
and `X-Powered-By` leaks the stack.

</details>

---

## 🏗️ Architecture

```
                    ┌──────────────────────────────────────────┐
                    │        Browser (Jinja2 + vanilla JS)     │
                    └───────────────────┬──────────────────────┘
                                        │ HTTP 127.0.0.1:8080
                    ┌───────────────────▼──────────────────────┐
                    │              Flask app factory           │
                    │  ┌────────────┬────────────┬───────────┐ │
                    │  │  public    │   auth     │  dashboard│ │
                    │  │  products  │  register  │  profile  │ │
                    │  │  news/FAQ  │  reset     │  KYC      │ │
                    │  └────────────┴────────────┴───────────┘ │
                    │  ┌────────────┬────────────┬───────────┐ │
                    │  │transactions│  claims    │  tickets  │ │
                    │  │ transfer   │ insurance  │  support  │ │
                    │  └────────────┴────────────┴───────────┘ │
                    │  ┌────────────┬────────────┬───────────┐ │
                    │  │  webhook   │  api/v1    │   admin   │ │
                    │  │   (SSRF)   │   (JWT)    │ (RBAC)    │ │
                    │  └────────────┴────────────┴───────────┘ │
                    │                                          │
                    │   app/lab.py  ◄── FEATURE_MATRIX (48)    │
                    │   every view asks: is_vulnerable?        │
                    └───────────────┬──────────────────────────┘
                                    │
                    ┌───────────────▼──────────────────────────┐
                    │  SQLite (WAL)  ·  uploads/  ·  data/     │
                    └──────────────────────────────────────────┘
```

**One source of truth.** Every vulnerable/secure decision goes through `LabPolicy`.
Adding a level or changing one feature's behaviour happens in one place — and the
whole application follows.

---

## 🗂️ Project Layout

```
nusabank/
├── app/
│   ├── __init__.py            # app factory, headers, error handlers
│   ├── lab.py                 # ⚙️  FEATURE_MATRIX — the level policy core
│   ├── security.py            # hashing, CSRF, JWT, uploads, rate limiting, traversal
│   ├── db.py                  # SQLite connection, queries, audit trail
│   ├── utils.py               # login_required, rupiah, pagination
│   ├── routes_public.py       # home, products, calculator, news, contact, FAQ
│   ├── routes_auth.py         # login, register, reset, change password
│   ├── routes_dashboard.py    # dashboard, profile, photo, PIN
│   ├── routes_transactions.py # transfer, history, receipt, CSV export
│   ├── routes_uploads.py      # file serving, KYC upload & download
│   ├── routes_claims.py       # policies, claim submission, attachments
│   ├── routes_tickets.py      # support tickets & comments
│   ├── routes_webhook.py      # e-wallet webhook (SSRF)
│   ├── routes_api.py          # REST /api/v1 (JWT, CORS, IDOR)
│   └── routes_admin.py        # back office (25 routes)
├── templates/                 # Jinja2 — public, auth, dashboard, admin
├── static/                    # custom CSS & vanilla JavaScript
├── db/
│   ├── schema.sql             # full schema
│   ├── seed.py                # 33 users, 60 accounts, 1,161 transactions
│   └── nusabank.db            # ready-to-run database
├── uploads/                   # KYC documents & claim attachments (dummy data)
├── tests/                     # verification suite — one module per feature area
│   ├── harness.py             # shared fixtures, level runner, pass/fail report
│   ├── verify_transactions.py # history, IDOR, SQLi, transfers, race condition
│   ├── verify_uploads_claims.py # KYC uploads, traversal, claims, tickets
│   ├── verify_ssrf_api.py     # e-wallet webhook (SSRF), JWT, CORS, rate limiting
│   ├── verify_admin.py        # back-office access control, SQLi, mass assignment
│   ├── verify_public_pages.py # news, contact form, calculator, DOM sink
│   └── run_all.py             # runs every module and summarises the result
├── docs/
│   ├── VULNS.md               # flaw catalogue + OWASP + payloads + fixes
│   ├── WALKTHROUGH.md         # step-by-step guide
│   └── CREDENTIALS.md         # accounts, PINs, flag locations
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🎭 Lab Data

Everything is synthetic: 30 customers at `@example.com`, 3 back-office accounts,
60 accounts, 1,161 transactions spread over 12 months, 15 policies, 10 claims,
20 tickets with comments, 12 news articles, and 14 KYC documents.

```text
Weak customers  budi01 / password        (PIN 123456)
                ani02  / 123456
                dewi03 / qwerty
                eko04  / nusabank
                fitri05/ admin123

Back office     admin       / NusaAdmin!2024      role: admin
                cs123       / NusaCS!2024         role: admin_cs
                finance456  / NusaFinance!2024    role: admin_finance
```

The full list — including 25 accounts with strong passwords and where every flag
lives — is in [`docs/CREDENTIALS.md`](docs/CREDENTIALS.md).

---

## 📖 Documentation

| Document | Contents |
|---|---|
| 📋 [`docs/VULNS.md`](docs/VULNS.md) | Full catalogue: flaw name, OWASP 2021 category, endpoint, affected levels, payload, impact, and fix. |
| 🧭 [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md) | Step-by-step path from recon to flags, with verified `curl` commands. |
| 🔑 [`docs/CREDENTIALS.md`](docs/CREDENTIALS.md) | Accounts, PINs, and the flag table. |

> **Spoilers.** The first two documents give away every answer. Try it yourself first.

---

## 🧪 Automated Verification

The `tests/` suite asserts what each level is supposed to do — all 432 checks across
the four levels must pass. Each module runs its scenarios on every level, compares the
observed values against a declared expectation table, and exits non-zero on the first
mismatch:

```bash
python tests/run_all.py            # everything, all four levels (~17 s)
python tests/run_all.py hard       # only one level
python tests/verify_admin.py       # only one module
```

| Module | Covers |
|---|---|
| `verify_transactions.py` | History, CSV export, IDOR, search/date SQLi, transfers, race condition |
| `verify_uploads_claims.py` | KYC uploads, path traversal, claim validation, ticket XSS |
| `verify_ssrf_api.py` | Webhook SSRF, JWT (`alg:none`, weak secret), CORS, rate limiting |
| `verify_admin.py` | Admin access control, login SQLi, mass assignment, command injection |
| `verify_public_pages.py` | News SQLi/XSS, contact form CSRF, calculator tampering |

Every level runs against a throwaway copy of `db/nusabank.db` and its own upload
directory, so the suite never touches your lab data. The SSRF module starts a real
loopback HTTP server, so the server-side fetch genuinely leaves the process. Sample
output:

```
=== admin panel - access control, SQLi, mass assignment, RCE ===
  easy      17 checks  ok
  medium    17 checks  ok
  hard      17 checks  ok
  patched   17 checks  ok

RESULT: 68/68 checks passed across 4 level(s)
```

Use it as a regression gate whenever you change the feature matrix, add a level, or
fix a flaw — a mismatch tells you exactly which check broke at which level.

---

## 🐳 Container Security Notes

The application is deliberately vulnerable, but the container is locked down as hard
as possible so the exercise cannot leak onto your host or network:

```yaml
ports:
  - "127.0.0.1:8080:8080"     # loopback only — never 0.0.0.0
read_only: true               # root filesystem is not writable
cap_drop: [ALL]               # no Linux capabilities
security_opt: [no-new-privileges:true]
tmpfs: [/tmp, /var/tmp]       # limited scratch space
```

Anything that must be written (database, uploads) lives on a separate volume.

---

## 🛠️ Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 · Flask 3.0 · Jinja2 3.1 · Werkzeug 3.0 |
| Data | SQLite 3 (WAL, foreign keys) |
| Auth | bcrypt (secure mode) · unsalted MD5 (vulnerable mode) · PyJWT |
| Frontend | HTML5 · CSS custom properties · vanilla JavaScript |
| Runtime | Docker `python:3.11-slim-bookworm` as a non-root uid |

---

## ⚠️ Disclaimer

This project exists for **education and security training**. The vulnerable code is
intentional and documented. Use it only against your own instance on a local machine
or an isolated VM. Applying the same techniques to a system without written
authorization is illegal.

If you use this lab in a class or workshop, keep one rule simple:
**loopback only, fictional data only, and always stop the container when you're done.**

<div align="center">

---

**Built to be studied — then fixed.**

`easy` → `medium` → `hard` → `patched`

</div>
