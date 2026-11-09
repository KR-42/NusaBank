#!/usr/bin/env python3
"""NusaBank Lab — idempotent database seeder.

Creates the schema (if missing) and populates a fictional banking dataset:
30 customers, 3 admins, accounts, 12 months of transactions, insurance,
claims, KYC placeholders, tickets, news, settings and lab flags.

Run:
    python db/seed.py            # seed only when the database is empty
    python db/seed.py --force    # wipe lab data and reseed

The script is safe to call on every container boot; it exits cleanly when
data already exists. All credentials are documented in docs/CREDENTIALS.md.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_FILE = Path(__file__).with_name("schema.sql")
DEFAULT_DB = BASE_DIR / "db" / "nusabank.db"

# Deterministic seed so repeated fresh setups look the same.
rng = random.Random(20240101)

# --- Fixed lab credentials --------------------------------------------------
# Passwords are intentionally mixed: the first five customers use trivial
# credentials so they can be cracked with a small dictionary on easy/medium.
CUSTOMERS = [
    ("budi01", "Budi Santoso", "password"),
    ("ani02", "Ani Wijaya", "123456"),
    ("dewi03", "Dewi Lestari", "qwerty"),
    ("eko04", "Eko Prasetyo", "nusabank"),
    ("fitri05", "Fitri Handayani", "admin123"),
    ("gunawan06", "Gunawan Saputra", "NusaBank!2024#06"),
    ("herlina07", "Herlina Kusuma", "NusaBank!2024#07"),
    ("indra08", "Indra Nugroho", "NusaBank!2024#08"),
    ("joko09", "Joko Setiawan", "NusaBank!2024#09"),
    ("kiki10", "Kiki Purnomo", "NusaBank!2024#10"),
    ("lina11", "Lina Wibowo", "NusaBank!2024#11"),
    ("mario12", "Mario Susanto", "NusaBank!2024#12"),
    ("nana13", "Nana Saputra", "NusaBank!2024#13"),
    ("odi14", "Odi Mulyadi", "NusaBank!2024#14"),
    ("putri15", "Putri Hidayat", "NusaBank!2024#15"),
    ("qori16", "Qori Rizky", "NusaBank!2024#16"),
    ("raka17", "Raka Darmawan", "NusaBank!2024#17"),
    ("sari18", "Sari Suryadi", "NusaBank!2024#18"),
    ("tino19", "Tino Hakim", "NusaBank!2024#19"),
    ("uli20", "Uli Ardiansyah", "NusaBank!2024#20"),
    ("vina21", "Vina Oktaviani", "NusaBank!2024#21"),
    ("wira22", "Wira Kurniawan", "NusaBank!2024#22"),
    ("xavi23", "Xavi Ramadhan", "NusaBank!2024#23"),
    ("yuni24", "Yuni Anggraini", "NusaBank!2024#24"),
    ("zaki25", "Zaki Firmansyah", "NusaBank!2024#25"),
    ("adi26", "Adi Kurnia", "NusaBank!2024#26"),
    ("cici27", "Cici Marlina", "NusaBank!2024#27"),
    ("deni28", "Deni Maulana", "NusaBank!2024#28"),
    ("eni29", "Eni Yuliana", "NusaBank!2024#29"),
    ("faisal30", "Faisal Abdurrahman", "NusaBank!2024#30"),
]

ADMINS = [
    ("admin", "NusaAdmin!2024", "Rudi Hartono", "admin@example.com", "admin"),
    ("cs123", "NusaCS!2024", "Siti Aminah", "cs@example.com", "admin_cs"),
    ("finance456", "NusaFinance!2024", "Bambang Sutrisno", "finance@example.com",
     "admin_finance"),
]

# Same PIN for every dummy customer so the transfer exercise is usable.
LAB_PIN = "123456"

STREETS = [
    "Jl. Merdeka", "Jl. Sudirman", "Jl. Thamrin", "Jl. Gatot Subroto",
    "Jl. Ahmad Yani", "Jl. Diponegoro", "Jl. Kartini", "Jl. Pahlawan",
]
CITIES = ["Jakarta", "Bandung", "Surabaya", "Medan", "Makassar", "Semarang",
          "Yogyakarta", "Denpasar"]


def md5_password(password: str) -> str:
    return "md5:" + hashlib.md5(password.encode()).hexdigest()


def bcrypt_password(password: str) -> str:
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()


def hash_secret(value: str, weak: bool) -> str:
    return md5_password(value) if weak else bcrypt_password(value)


def make_address() -> str:
    return f"{rng.choice(STREETS)} No. {rng.randint(1, 220)}, {rng.choice(CITIES)}"


def make_phone() -> str:
    return f"08{rng.randint(11000000, 99999999)}"


def account_number(user_id: int) -> str:
    # 10 digits, deterministic and unique per user/account.
    return f"10{user_id:06d}{rng.randint(10, 99)}"


def ref(prefix: str, counter: int) -> str:
    return f"{prefix}-{datetime.now():%Y%m%d}-{counter:06d}"


def reset_data(conn):
    tables = [
        "webhook_logs", "webhooks", "lab_flags", "audit_logs", "login_attempts",
        "api_tokens", "remember_tokens", "reset_tokens", "ticket_comments",
        "tickets", "claims", "insurance_policies", "kyc_documents",
        "transactions", "cards", "accounts", "contacts", "news",
        "users", "roles", "settings",
    ]
    for table in tables:
        conn.execute(f"DELETE FROM {table}")
    # Reset AUTOINCREMENT counters so a reseed produces the same ids/files.
    conn.execute("DELETE FROM sqlite_sequence")
    conn.commit()


def clean_generated_uploads():
    """Remove files produced by a previous seed run (keeps user uploads)."""
    uploads = Path(os.environ.get("NUSABANK_UPLOADS", str(BASE_DIR / "uploads")))
    for pattern in ("kyc/*", "claim_*.pdf"):
        for path in uploads.glob(pattern):
            try:
                path.unlink()
            except OSError:
                pass


def seed(force=False):
    db_path = Path(os.environ.get("NUSABANK_DB", str(DEFAULT_DB)))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()

    existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if existing and not force:
        print(f"[=] Database already seeded ({existing} users). Nothing to do.")
        print("    Use --force to wipe and reseed.")
        conn.close()
        return False
    if existing and force:
        print("[!] --force: wiping existing lab data")
        reset_data(conn)
        clean_generated_uploads()

    # Password hashing follows the active lab level. Reset the DB when you
    # switch level so stored hashes match the intended exercise.
    level = os.environ.get("LAB_LEVEL", "easy").strip().lower()
    weak_hashes = level in ("easy", "medium")
    now = datetime.now()

    # --- Roles -------------------------------------------------------------
    conn.executemany(
        "INSERT OR IGNORE INTO roles(id, name, description) VALUES(?,?,?)",
        [
            (1, "user", "Nasabah biasa"),
            (2, "admin", "Super administrator"),
            (3, "admin_cs", "Administrator layanan pelanggan"),
            (4, "admin_finance", "Administrator keuangan & audit"),
        ],
    )

    # --- Admins ------------------------------------------------------------
    admin_ids = []
    for username, password, full_name, email, role_name in ADMINS:
        role_id = conn.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()["id"]
        cur = conn.execute(
            "INSERT INTO users(username, email, password_hash, pin_hash, full_name, phone, "
            "address, role_id, kyc_status, is_active) VALUES(?,?,?,?,?,?,?,?,?,1)",
            (username, email, hash_secret(password, weak_hashes),
             hash_secret(LAB_PIN, weak_hashes), full_name, make_phone(),
             "Kantor Pusat NusaBank, Jakarta", role_id, "verified"),
        )
        admin_ids.append(cur.lastrowid)

    # --- Customers ---------------------------------------------------------
    customer_rows = []
    for idx, (username, full_name, password) in enumerate(CUSTOMERS):
        cur = conn.execute(
            "INSERT INTO users(username, email, password_hash, pin_hash, full_name, phone, "
            "address, role_id, kyc_status, is_active) VALUES(?,?,?,?,?,?,?,?,?,1)",
            (
                username, f"{username}@example.com",
                hash_secret(password, weak_hashes),
                hash_secret(LAB_PIN, weak_hashes),
                full_name, make_phone(), make_address(), 1,
                "verified" if idx % 4 else "pending",
            ),
        )
        customer_rows.append({"id": cur.lastrowid, "username": username,
                              "full_name": full_name})

    # --- Accounts (1–3 per customer) --------------------------------------
    accounts = []  # dicts: id,user_id,number
    for idx, user in enumerate(customer_rows):
        count = 1 + (idx % 3)  # 1, 2 or 3
        for n in range(count):
            number = account_number(user["id"] + n * 100)
            # Ensure uniqueness even if the deterministic scheme collides.
            while conn.execute("SELECT 1 FROM accounts WHERE account_number=?",
                               (number,)).fetchone():
                number = str(int(number) + 1)
            cur = conn.execute(
                "INSERT INTO accounts(user_id, account_number, account_type, label, "
                "balance) VALUES(?,?,?,?,0)",
                (user["id"], number,
                 ["tabungan", "giro", "deposito"][n % 3],
                 ["Rekening Utama", "Rekening Gaji", "Rekening Deposito"][n % 3]),
            )
            accounts.append({"id": cur.lastrowid, "user_id": user["id"],
                             "number": number, "user": user})

    # Primary debit card per customer
    for idx, user in enumerate(customer_rows):
        primary = next(a for a in accounts if a["user_id"] == user["id"])
        conn.execute(
            "INSERT INTO cards(user_id, account_id, card_number, card_type, expiry, "
            "limit_amount) VALUES(?,?,?,?,?,?)",
            (user["id"], primary["id"],
             f"4{rng.randint(10**14, 10**15 - 1)}", "debit",
             f"{rng.randint(1, 12):02d}/{28 + rng.randint(0, 3)}",
             rng.choice([5000000, 10000000, 25000000])),
        )

    # --- Transactions: 20–50 per customer over the last 12 months ---------
    tx_rows = []
    tx_counter = 0
    tx_counts = {u["id"]: 0 for u in customer_rows}  # per-customer tally (20..50)
    categories = ["transfer", "belanja", "tagihan", "gaji", "tarik_tunai",
                  "topup", "bunga"]
    merchant_names = ["PLN", "PDAM", "Telkom", "BPJS", "Indomaret", "Alfamart",
                      "Tokopedia", "Shopee", "GoFood", "Grab"]

    def add_tx(account, signed_amount, tx_type, category, description,
               counterparty_name=None, counterparty_account=None,
               related_account_id=None, direction=None, when=None):
        nonlocal tx_counter
        tx_counter += 1
        tx_counts[account["user_id"]] += 1
        tx_rows.append({
            "ref_no": ref("TRX", tx_counter),
            "account_id": account["id"],
            "related_account_id": related_account_id,
            "direction": direction or ("IN" if signed_amount > 0 else "OUT"),
            "tx_type": tx_type,
            "amount": abs(int(signed_amount)),
            "signed": int(signed_amount),
            "counterparty_name": counterparty_name,
            "counterparty_account": counterparty_account,
            "description": description,
            "category": category,
            "created_at": when or (now - timedelta(
                days=rng.randint(1, 365), minutes=rng.randint(0, 1439)
            )).strftime("%Y-%m-%d %H:%M:%S"),
        })

    for idx, user in enumerate(customer_rows):
        user_accounts = [a for a in accounts if a["user_id"] == user["id"]]
        primary = user_accounts[0]
        n_tx = 20 + (idx * 7) % 31  # total 20..50 transactions per customer

        # Monthly salary credit on the primary account (12 of the total)
        for m in range(12):
            when = (now - timedelta(days=30 * m + rng.randint(0, 4))).strftime(
                "%Y-%m-%d %H:%M:%S")
            add_tx(primary, rng.randint(6000000, 15000000), "deposit", "gaji",
                   "Gaji bulanan", counterparty_name="PT Nusantara Digital",
                   counterparty_account="8820010011", direction="IN", when=when)

        # Fill up to n_tx for this customer (12 salary rows already added above;
        # transfers also credit the *recipient*, which counts toward their tally).
        while tx_counts[user["id"]] < n_tx:
            account = rng.choice(user_accounts)
            when = (now - timedelta(days=rng.randint(1, 365),
                                    minutes=rng.randint(0, 1439))).strftime(
                "%Y-%m-%d %H:%M:%S")
            roll = rng.random()
            if roll < 0.45:
                # Only credit recipients that still have room under the 50 cap.
                candidates = [u for u in customer_rows
                              if u["id"] != user["id"] and tx_counts[u["id"]] < 50]
                if not candidates:
                    continue
                other = rng.choice(candidates)
                dest_pool = [a for a in accounts if a["user_id"] == other["id"]]
                if not dest_pool:
                    continue
                dest = rng.choice(dest_pool)
                amount = rng.randint(50000, 5000000)
                add_tx(account, -amount, "transfer", "transfer",
                       f"Transfer ke {other['full_name']}",
                       counterparty_name=other["full_name"],
                       counterparty_account=dest["number"],
                       related_account_id=dest["id"], direction="OUT", when=when)
                add_tx(dest, amount, "transfer", "transfer",
                       f"Transfer dari {user['full_name']}",
                       counterparty_name=user["full_name"],
                       counterparty_account=account["number"],
                       related_account_id=account["id"], direction="IN", when=when)
            elif roll < 0.72:
                merchant = rng.choice(merchant_names)
                amount = rng.randint(15000, 1500000)
                add_tx(account, -amount, "payment", "belanja",
                       f"Pembayaran {merchant}", counterparty_name=merchant,
                       direction="OUT", when=when)
            elif roll < 0.86:
                amount = rng.randint(150000, 2000000)
                add_tx(account, amount, "topup", "topup", "Top-up dompet digital",
                       counterparty_name="NusaPay", direction="IN", when=when)
            else:
                amount = rng.randint(20000, 750000)
                add_tx(account, -amount, "withdrawal", "tarik_tunai",
                       "Penarikan tunai ATM", counterparty_name="ATM NusaBank",
                       direction="OUT", when=when)

    # Compute a coherent running balance per account.
    by_account = {}
    for row in tx_rows:
        row["signed"] = -row["amount"] if row["direction"] == "OUT" else row["amount"]
        by_account.setdefault(row["account_id"], []).append(row)

    for account in accounts:
        rows = sorted(by_account.get(account["id"], []),
                      key=lambda r: r["created_at"])
        if not rows:
            opening = rng.randint(500000, 5000000)
            conn.execute("UPDATE accounts SET balance=? WHERE id=?",
                         (opening, account["id"]))
            continue
        # Opening balance large enough to keep every running balance positive.
        min_prefix, running = 0, 0
        for r in rows:
            running += r["signed"]
            min_prefix = min(min_prefix, running)
        opening = max(250000, -min_prefix + rng.randint(500000, 3000000))
        balance = opening
        for r in rows:
            balance += r["signed"]
            r["balance_after"] = balance
        conn.execute("UPDATE accounts SET balance=? WHERE id=?",
                     (balance, account["id"]))

    conn.executemany(
        "INSERT INTO transactions(ref_no, account_id, related_account_id, direction, "
        "tx_type, amount, counterparty_name, counterparty_account, description, category, "
        "status, balance_after, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(r["ref_no"], r["account_id"], r["related_account_id"], r["direction"],
          r["tx_type"], r["amount"], r["counterparty_name"], r["counterparty_account"],
          r["description"], r["category"], "success", r["balance_after"],
          r["created_at"]) for r in tx_rows],
    )

    # --- KYC documents -----------------------------------------------------
    uploads = Path(os.environ.get(
        "NUSABANK_UPLOADS", str(BASE_DIR / "uploads")))
    (uploads / "kyc").mkdir(parents=True, exist_ok=True)
    (uploads / "legacy").mkdir(parents=True, exist_ok=True)

    for idx, user in enumerate(customer_rows[:14]):
        doc_type = "ktp" if idx % 2 == 0 else "npwp"
        stored = f"{idx + 1:02d}_{doc_type}_{user['username']}.jpg"
        target = uploads / "kyc" / stored
        target.write_text(
            f"[fake {doc_type.upper()} scan]\nNama: {user['full_name']}\n"
            f"LAB_PLACEHOLDER\nFLAG{{kyc_file_{idx + 1}}}\n",
            encoding="utf-8",
        )
        conn.execute(
            "INSERT INTO kyc_documents(user_id, doc_type, stored_name, original_name, "
            "mime_type, size_bytes, status, note) VALUES(?,?,?,?,?,?,?,?)",
            (user["id"], doc_type, stored, f"{doc_type}_{user['username']}.jpg",
             "image/jpeg", target.stat().st_size,
             ["verified", "pending", "rejected"][idx % 3],
             "Contoh dokumen lab."),
        )

    # Flag hidden in a legacy file reachable via the download exercise.
    (uploads / "legacy" / "flag.txt").write_text(
        "FLAG{flag_in_file_system}\n", encoding="utf-8")

    # --- Insurance & claims ------------------------------------------------
    policy_ids = []
    for idx, user in enumerate(customer_rows[:15]):
        product = "jiwa" if idx % 2 == 0 else "kendaraan"
        start = now - timedelta(days=rng.randint(30, 330))
        end = start + timedelta(days=365)
        cur = conn.execute(
            "INSERT INTO insurance_policies(user_id, policy_no, product, coverage, "
            "premium, start_date, end_date, status) VALUES(?,?,?,?,?,?,?,?)",
            (user["id"], f"POL-{user['id']:04d}-{idx + 1:03d}", product,
             rng.choice([100000000, 250000000, 500000000]),
             rng.choice([50000, 150000, 300000]),
             start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d"), "active"),
        )
        policy_ids.append((cur.lastrowid, user["id"], product))

    for idx, (policy_id, user_id, product) in enumerate(policy_ids[:10]):
        claim_no = f"CLM-{user_id:04d}-{idx + 1:03d}"
        attached = f"claim_{claim_no}.pdf"
        (uploads / attached).write_text(
            f"Fake claim attachment {claim_no}\nFLAG{{claim_file_{idx + 1}}}\n",
            encoding="utf-8",
        )
        coverage = conn.execute("SELECT coverage FROM insurance_policies WHERE id = ?",
                                (policy_id,)).fetchone()["coverage"]
        # Keep every seeded claim inside its policy's coverage so the data is
        # internally consistent at `patched` level too.
        amount = rng.randint(5000000, min(100000000, coverage))
        conn.execute(
            "INSERT INTO claims(claim_no, policy_id, user_id, amount, description, "
            "attachment, status, admin_note) VALUES(?,?,?,?,?,?,?,?)",
            (claim_no, policy_id, user_id, amount,
             f"Klaim asuransi {product} — contoh data lab.", attached,
             ["submitted", "approved", "rejected"][idx % 3],
             "Internal: dokumen telah diverifikasi oleh tim klaim."),
        )

    # --- Tickets & comments ------------------------------------------------
    subjects = [
        "Transfer tidak masuk ke rekening tujuan",
        "Kartu debit tidak bisa digunakan di ATM",
        "Saldo tidak sesuai setelah transaksi",
        "Tidak bisa login ke aplikasi mobile",
        "Pertanyaan tentang bunga deposito",
        "Permintaan penggantian kartu",
    ]
    for idx, user in enumerate(customer_rows[:20]):
        ticket_no = f"TCK-{user['id']:04d}-{idx + 1:03d}"
        cur = conn.execute(
            "INSERT INTO tickets(ticket_no, user_id, subject, category, priority, "
            "status) VALUES(?,?,?,?,?,?)",
            (ticket_no, user["id"], subjects[idx % len(subjects)],
             ["umum", "teknis", "keluhan", "saran"][idx % 4],
             ["low", "normal", "high"][idx % 3],
             ["open", "in_progress", "closed"][idx % 3]),
        )
        ticket_id = cur.lastrowid
        conn.execute(
            "INSERT INTO ticket_comments(ticket_id, user_id, author_name, body) "
            "VALUES(?,?,?,?)",
            (ticket_id, user["id"], user["full_name"],
             f"Halo, saya mengalami kendala ini. Mohon dibantu. Ref {ticket_no}"),
        )
        conn.execute(
            "INSERT INTO ticket_comments(ticket_id, user_id, author_name, body, "
            "is_internal) VALUES(?,?,?,?,1)",
            (ticket_id, None, "Admin CS",
             "Internal note: cek mutasi dan log transaksi nasabah."),
        )

    # --- News --------------------------------------------------------------
    news_items = [
        ("promo-tabungan-nusa-prima", "Promo Tabungan Nusa Prima: Bunga 3,5%",
         "Promo", "Bunga spesial untuk pembukaan rekening baru."),
        ("layanan-pelanggan-24-jam", "Layanan Pelanggan Kini 24 Jam",
         "Layanan", "Tim NusaBank siap membantu kapan pun Anda butuh."),
        ("keamanan-transaksi-digital", "Cara Menjaga Keamanan Transaksi Digital",
         "Keamanan", "Tips melindungi PIN dan data pribadi dari penipuan."),
        ("asuransi-kendaraan-baru", "Asuransi Kendaraan NusaDrive Kini All-Risk",
         "Produk", "Perlindungan menyeluruh untuk kendaraan Anda."),
        ("kartu-kredit-platinum", "NusaCard Platinum: Cashback 5%",
         "Produk", "Penawaran cashback untuk transaksi bulan ini."),
        ("jaringan-cabang-baru", "10 Cabang Baru di Seluruh Indonesia",
         "Perusahaan", "NusaBank memperluas jaringan layanan."),
        ("penghargaan-bank-digital", "NusaBank Raih Penghargaan Bank Digital 2024",
         "Perusahaan", "Penghargaan dari majalah finansial nasional."),
        ("dukungan-umkm", "Program Pinjaman UMKM Bunga Rendah",
         "Promo", "Dukungan modal untuk pelaku usaha mikro."),
        ("program-loyalitas", "Program Loyalitas NusaRewards",
         "Promo", "Kumpulkan poin dari setiap transaksi."),
        ("teknologi-ai", "AI untuk Analisis Risiko Transaksi",
         "Teknologi", "Deteksi penipuan yang lebih cepat dan akurat."),
        ("perlindungan-data", "Komitmen Perlindungan Data Pribadi",
         "Keamanan", "Kebijakan privasi dan keamanan data nasabah."),
        ("transfer-online-baru", "Fitur Transfer Antar Bank Satu Klik",
         "Produk", "Pengalaman transfer yang lebih praktis."),
    ]
    for offset, (slug, title, category, excerpt) in enumerate(news_items):
        body = (
            f"{excerpt}\n\n"
            "NusaBank terus berkomitmen memberikan layanan terbaik bagi seluruh "
            "nasabah. Informasi pada artikel ini merupakan bagian dari data "
            "simulasi untuk lingkungan latihan keamanan.\n\n"
            f"FLAG{{news_{offset + 1}}}"
        )
        conn.execute(
            "INSERT INTO news(slug, title, category, excerpt, body, author, "
            "is_published, published_at) VALUES(?,?,?,?,?,?,1,?)",
            (slug, title, category, excerpt, body, "Redaksi NusaBank",
             (now - timedelta(days=offset * 8 + 2)).strftime("%Y-%m-%d %H:%M:%S")),
        )

    # --- Contacts (public form submissions) --------------------------------
    conn.execute(
        "INSERT INTO contacts(name, email, phone, subject, message) VALUES(?,?,?,?,?)",
        ("Rina Wijaya", "rina@example.com", "081234567890", "Info deposito",
         "Saya ingin bertanya mengenai suku bunga deposito 12 bulan."),
    )

    # --- Settings & flags --------------------------------------------------
    settings = [
        ("site_name", "NusaBank"),
        ("site_tagline", "Bank Digital Indonesia"),
        ("maintenance_mode", "0"),
        ("support_email", "care@nusabank.example.com"),
        ("transfer_fee", "2500"),
        ("deposit_rate", "4.25"),
        ("loan_rate", "8.5"),
        ("webhook_secret", "whsec_nusabank_lab_dev"),
        ("webhook_allowlist", "partner.nusabank.example.com"),
        ("api_base_url", "http://127.0.0.1:8080/api/v1"),
        ("flag_admin_panel", "FLAG{flag_in_admin_panel}"),
    ]
    conn.executemany(
        "INSERT INTO settings(key, value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        settings,
    )

    lab_flags = [
        ("db_flag", "FLAG{flag_in_database}", "users.address (admin) / settings"),
        ("file_flag", "FLAG{flag_in_file_system}", "uploads/legacy/flag.txt"),
        ("admin_flag", "FLAG{flag_in_admin_panel}", "settings.flag_admin_panel"),
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO lab_flags(name, value, location) VALUES(?,?,?)",
        lab_flags,
    )

    # --- Hidden flag in an admin's address column -------------------------
    conn.execute(
        "UPDATE users SET address = ? WHERE username = 'admin'",
        ("Kantor Pusat NusaBank, Jakarta — FLAG{flag_in_database}",),
    )

    conn.commit()
    conn.close()

    print(f"[+] Seed complete: {len(CUSTOMERS)} customers, {len(ADMINS)} admins, "
          f"{len(accounts)} accounts, {len(tx_rows)} transactions")
    print(f"    Database : {db_path}")
    print(f"    Uploads  : {uploads}")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Seed the NusaBank lab database")
    parser.add_argument("--force", action="store_true",
                        help="delete existing lab data and reseed")
    args = parser.parse_args(argv)
    seed(force=args.force)


if __name__ == "__main__":
    main()