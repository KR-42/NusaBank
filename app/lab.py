"""
Central lab policy for NusaBank.

Every vulnerable / hardened code path in this application asks this module
`is_vulnerable(feature)` before choosing a behaviour.  Keeping the decision in
one place makes the lab easy to flip between difficulties and easy to audit:

    LAB_LEVEL=easy      -> every training vulnerability active, no defences
    LAB_LEVEL=medium    -> basic defences that can be bypassed
    LAB_LEVEL=hard      -> real defences, one subtle flaw per module remains
    LAB_LEVEL=patched   -> reference secure implementation

The table below is the single source of truth.  Read it as a matrix:
rows are lab features, columns are levels.  `V` = vulnerable, `P` = patched.
"""

import os
import secrets

LEVELS = ("easy", "medium", "hard", "patched")

# Feature matrix -------------------------------------------------------------
# Feature keys are stable identifiers used across blueprints and templates.
FEATURE_MATRIX = {
    # key                         easy medium hard patched
    "sqli_login":               ("V", "V", "P", "P"),
    "sqli_search":              ("V", "V", "V", "P"),
    "sqli_transactions":        ("V", "V", "V", "P"),
    "xss_reflected":            ("V", "V", "V", "P"),
    "xss_stored":               ("V", "V", "V", "P"),
    "xss_dom":                  ("V", "V", "V", "P"),
    "weak_password_policy":     ("V", "V", "P", "P"),
    "weak_password_hash":       ("V", "V", "P", "P"),
    "user_enumeration":         ("V", "V", "P", "P"),
    "no_account_lockout":       ("V", "V", "P", "P"),
    "predictable_reset_token":  ("V", "V", "P", "P"),
    "session_fixation":         ("V", "V", "P", "P"),
    "insecure_remember":        ("V", "V", "P", "P"),
    "idor_transactions":        ("V", "V", "V", "P"),
    "idor_kyc":                 ("V", "V", "P", "P"),
    "idor_claims":              ("V", "V", "P", "P"),
    "idor_tickets":             ("V", "V", "P", "P"),
    "idor_profile":             ("V", "V", "V", "P"),
    "claim_amount_bypass":      ("V", "V", "P", "P"),
    "claim_cumulative_bypass":  ("P", "P", "V", "P"),
    "internal_note_exposure":   ("V", "V", "V", "P"),
    "ticket_xss":               ("V", "V", "P", "P"),
    "admin_no_role_check":      ("V", "V", "P", "P"),
    "admin_role_separation":    ("V", "V", "V", "P"),   # hard: no per-action RBAC
    "http_method_tampering":    ("V", "V", "P", "P"),
    "mass_assignment":          ("V", "V", "V", "P"),
    "insecure_upload":          ("V", "V", "P", "P"),
    "ssrf_webhook":             ("V", "V", "P", "P"),
    "command_injection":        ("V", "V", "P", "P"),
    "path_traversal":           ("V", "V", "P", "P"),
    "csrf":                     ("V", "V", "P", "P"),
    "weak_jwt":                 ("V", "V", "P", "P"),
    "permissive_cors":          ("V", "V", "P", "P"),
    "api_no_rate_limit":        ("V", "V", "P", "P"),
    "negative_transfer":        ("V", "V", "V", "P"),
    "race_condition":           ("V", "V", "P", "P"),
    "pin_bypass":               ("V", "V", "P", "P"),
    "calc_parameter_tampering": ("V", "V", "V", "P"),
    "open_redirect":            ("V", "V", "V", "P"),
    "verbose_errors":           ("V", "V", "P", "P"),
    "debug_endpoint":           ("V", "V", "P", "P"),
    "exposed_backup":           ("V", "V", "P", "P"),
    "sensitive_robots":         ("V", "V", "V", "P"),
    "verbose_server_header":    ("V", "V", "P", "P"),
    "insecure_cookies":         ("V", "V", "P", "P"),
    "missing_security_headers": ("V", "V", "P", "P"),
    "xxe_import":               ("V", "P", "P", "P"),
    "insecure_deserialization": ("V", "V", "P", "P"),
    # Stacked defences (not really "holes", used by helpers)
    "prepared_statements":      ("P", "P", "P", "P"),
    "rate_limiting":            ("P", "P", "V", "P"),   # hard: enabled but bypassable
    "csrf_tokens":              ("P", "P", "V", "P"),
    "output_escaping":          ("P", "P", "P", "P"),
    "jwt_expiry":               ("P", "P", "P", "P"),
    "atomic_transactions":      ("P", "P", "V", "P"),   # hard: subtle race window
}

# The single subtle flaw left open per module on `hard` is represented by the
# "V" entries in the hard column above (SQLi via time-based blind on the
# transaction ID, mass assignment on a nested profile field, negative amount,
# calc parameter tampering, open redirect, the sensitive robots.txt, and the
# back-office panel that authenticates admins but never separates their duties).


def normalize_level(value):
    value = (value or "").strip().lower()
    return value if value in LEVELS else "easy"


class LabPolicy:
    """Immutable view over the feature matrix for one active level."""

    def __init__(self, level=None):
        self.level = normalize_level(level or os.environ.get("LAB_LEVEL", "easy"))

    # Core question used everywhere ---------------------------------------
    def is_vulnerable(self, feature):
        try:
            row = FEATURE_MATRIX[feature]
        except KeyError:
            raise KeyError(f"Unknown lab feature: {feature!r}")
        return row[LEVELS.index(self.level)] == "V"

    def is_patched(self, feature):
        return not self.is_vulnerable(feature)

    # Convenience groupings ------------------------------------------------
    @property
    def is_easy(self):
        return self.level == "easy"

    @property
    def is_medium(self):
        return self.level == "medium"

    @property
    def is_hard(self):
        return self.level == "hard"

    @property
    def level_is_patched(self):
        return self.level == "patched"

    @property
    def strong_auth(self):
        return not self.is_vulnerable("weak_password_policy")

    def describe(self):
        return {
            "easy": "Celah terbuka lebar, tanpa proteksi. Cocok untuk pemula.",
            "medium": "Proteksi dasar yang bisa dilewati (blacklist, validasi klien).",
            "hard": "Proteksi berlapis dengan satu celah halus per modul.",
            "patched": "Implementasi acuan aman. Semua celah ditutup.",
        }[self.level]


def current_policy():
    """Fresh policy from the environment (cheap; matrix is static)."""
    return LabPolicy(os.environ.get("LAB_LEVEL", "easy"))


def weak_jwt_secret():
    """Deliberately weak secret used on easy/medium levels."""
    return "nusabank123"


def random_secret():
    return secrets.token_urlsafe(48)