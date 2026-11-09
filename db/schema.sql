-- NusaBank lab schema (SQLite)
-- All data is fictional. Intended for isolated, local penetration-testing practice only.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------------------
-- Roles & users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE,
    email          TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    pin_hash       TEXT,
    full_name      TEXT NOT NULL,
    phone          TEXT,
    address        TEXT,
    photo          TEXT,
    role_id        INTEGER NOT NULL REFERENCES roles(id),
    is_active      INTEGER NOT NULL DEFAULT 1,
    kyc_status     TEXT NOT NULL DEFAULT 'pending',   -- pending|verified|rejected
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT,
    last_login_at  TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role_id);

-- ---------------------------------------------------------------------------
-- Rekening & transaksi
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_number TEXT NOT NULL UNIQUE,
    account_type   TEXT NOT NULL DEFAULT 'tabungan',  -- tabungan|giro|deposito
    label          TEXT,
    balance        INTEGER NOT NULL DEFAULT 0,         -- rupiah, integer
    currency       TEXT NOT NULL DEFAULT 'IDR',
    status         TEXT NOT NULL DEFAULT 'active',
    opened_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_number ON accounts(account_number);

CREATE TABLE IF NOT EXISTS transactions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ref_no            TEXT NOT NULL UNIQUE,
    account_id        INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    related_account_id INTEGER REFERENCES accounts(id),
    direction         TEXT NOT NULL,                  -- IN|OUT
    tx_type           TEXT NOT NULL,                  -- transfer|payment|topup|fee|interest|withdrawal
    amount            INTEGER NOT NULL,
    counterparty_name TEXT,
    counterparty_account TEXT,
    description       TEXT,
    category          TEXT,
    status            TEXT NOT NULL DEFAULT 'success',
    balance_after     INTEGER,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tx_account ON transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_tx_created ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_tx_ref ON transactions(ref_no);

CREATE TABLE IF NOT EXISTS cards (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id    INTEGER REFERENCES accounts(id),
    card_number   TEXT NOT NULL,
    card_type     TEXT NOT NULL DEFAULT 'debit',      -- debit|credit
    brand         TEXT NOT NULL DEFAULT 'NusaCard',
    expiry        TEXT,
    limit_amount  INTEGER DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cards_user ON cards(user_id);

-- ---------------------------------------------------------------------------
-- Asuransi
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS insurance_policies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    policy_no     TEXT NOT NULL UNIQUE,
    product       TEXT NOT NULL,                      -- jiwa|kendaraan
    coverage      INTEGER NOT NULL,
    premium       INTEGER NOT NULL,
    start_date    TEXT,
    end_date      TEXT,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_policies_user ON insurance_policies(user_id);

CREATE TABLE IF NOT EXISTS claims (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    claim_no     TEXT NOT NULL UNIQUE,
    policy_id    INTEGER NOT NULL REFERENCES insurance_policies(id),
    user_id      INTEGER NOT NULL REFERENCES users(id),
    amount       INTEGER NOT NULL,
    description  TEXT,
    attachment   TEXT,
    status       TEXT NOT NULL DEFAULT 'submitted',   -- submitted|approved|rejected
    admin_note   TEXT,
    reviewed_by  INTEGER REFERENCES users(id),
    reviewed_at  TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_claims_user ON claims(user_id);

-- ---------------------------------------------------------------------------
-- KYC documents
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kyc_documents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    doc_type      TEXT NOT NULL,                      -- ktp|npwp|selfie|lainnya
    stored_name   TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type     TEXT,
    size_bytes    INTEGER DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'pending',
    note          TEXT,
    reviewed_by   INTEGER REFERENCES users(id),
    reviewed_at   TEXT,
    uploaded_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_kyc_user ON kyc_documents(user_id);

-- ---------------------------------------------------------------------------
-- Tiket pengaduan
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tickets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_no   TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject     TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'umum',
    priority    TEXT NOT NULL DEFAULT 'normal',
    status      TEXT NOT NULL DEFAULT 'open',          -- open|in_progress|closed
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tickets_user ON tickets(user_id);

CREATE TABLE IF NOT EXISTS ticket_comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id   INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    user_id     INTEGER REFERENCES users(id),
    author_name TEXT,
    body        TEXT NOT NULL,
    is_internal INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket ON ticket_comments(ticket_id);

-- ---------------------------------------------------------------------------
-- Konten publik
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS news (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    slug         TEXT NOT NULL UNIQUE,
    title        TEXT NOT NULL,
    category     TEXT NOT NULL DEFAULT 'Berita',
    excerpt      TEXT,
    body         TEXT NOT NULL,
    author       TEXT NOT NULL DEFAULT 'Redaksi NusaBank',
    image        TEXT,
    is_published INTEGER NOT NULL DEFAULT 1,
    views        INTEGER NOT NULL DEFAULT 0,
    published_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_news_published ON news(published_at);

CREATE TABLE IF NOT EXISTS contacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    phone      TEXT,
    subject    TEXT,
    message    TEXT NOT NULL,
    is_read    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- Auth & API artifacts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reset_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reset_token ON reset_tokens(token);

CREATE TABLE IF NOT EXISTS remember_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    selector      TEXT NOT NULL UNIQUE,
    validator_hash TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label      TEXT NOT NULL DEFAULT 'default',
    token      TEXT NOT NULL,
    expires_at TEXT,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT,
    ip         TEXT,
    success    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(username, created_at);

-- ---------------------------------------------------------------------------
-- Audit, settings, webhooks, lab flags
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),
    actor      TEXT,
    action     TEXT NOT NULL,
    detail     TEXT,
    ip         TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhooks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label       TEXT NOT NULL,
    url         TEXT NOT NULL,
    last_status INTEGER,
    last_body   TEXT,
    last_called_at TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS lab_flags (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL UNIQUE,
    value    TEXT NOT NULL,
    location TEXT
);

CREATE TABLE IF NOT EXISTS webhook_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id INTEGER REFERENCES webhooks(id) ON DELETE CASCADE,
    user_id    INTEGER,
    url        TEXT,
    status     INTEGER,
    response   TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------------------
-- Views for convenience
-- ---------------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS v_user_overview AS
SELECT u.id, u.username, u.email, u.full_name, u.kyc_status, u.is_active,
       r.name AS role,
       (SELECT COUNT(*) FROM accounts a WHERE a.user_id = u.id) AS account_count,
       (SELECT COALESCE(SUM(a.balance), 0) FROM accounts a WHERE a.user_id = u.id) AS total_balance
FROM users u JOIN roles r ON r.id = u.role_id;