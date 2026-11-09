"""Shared helpers for the NusaBank verification suite.

Every ``verify_*.py`` module follows the same shape:

* ``run(level)`` exercises one lab level and returns a flat
  ``{check_name: observed_value}`` mapping;
* ``EXPECT`` declares, as a 4-tuple in ``LEVELS`` order, the value each level
  must produce;
* ``run_module()`` compares the two, prints a per-level summary and returns a
  process exit code (0 = all checks passed).

Each level runs against a throwaway copy of ``db/nusabank.db`` and a throwaway
``uploads`` directory, so the suite never mutates the shipped lab data.
"""

import contextlib
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

SRC_DB = os.path.join(ROOT, "db", "nusabank.db")
SRC_UPLOADS = os.path.join(ROOT, "uploads")

LEVELS = ("easy", "medium", "hard", "patched")

CUSTOMER = ("budi01", "password")
ADMIN = ("admin", "NusaAdmin!2024")


@contextlib.contextmanager
def lab(level):
    """Point the app at a private copy of the database and upload directory."""
    tmpdir = tempfile.mkdtemp(prefix=f"nusabank-{level}-")
    db_path = os.path.join(tmpdir, f"nusabank-{level}.db")
    shutil.copyfile(SRC_DB, db_path)
    uploads = os.path.join(tmpdir, f"uploads-{level}")
    shutil.copytree(SRC_UPLOADS, uploads, dirs_exist_ok=True)

    os.environ.update(
        LAB_LEVEL=level,
        NUSABANK_DB=db_path,
        NUSABANK_UPLOADS=uploads,
        # patched sets SESSION_COOKIE_SECURE, which a test client would drop.
        NUSABANK_COOKIE_SECURE="0",
    )

    from app import create_app
    from app.security import _RATE

    _RATE.clear()
    app = create_app({"DB_PATH": db_path, "UPLOAD_DIR": uploads})
    try:
        yield app, db_path, uploads, tmpdir
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def csrf(client, path="/login"):
    """Fetch a CSRF token from a page; easy/medium render a static one."""
    body = client.get(path).data.decode("utf-8", "replace")
    match = re.search(r'name="csrf_token" value="([^"]+)"', body)
    return match.group(1) if match else "nusabank-csrf-static-token"


def login(client, username=CUSTOMER[0], password=CUSTOMER[1]):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=False)


def rows(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def execute(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def text(resp):
    return resp.data.decode("utf-8", "replace")


def run_module(title, run, expect, levels=None):
    """Run ``run`` on every level, compare against ``expect``, return exit code."""
    levels = levels or list(LEVELS)
    total = 0
    failures = []

    print(f"\n=== {title} ===")
    for level in levels:
        try:
            recorded = run(level)
        except Exception as exc:  # noqa: BLE001
            failures.append((level, "<module crashed>", "no exception", repr(exc)))
            print(f"  {level:<8} CRASH   {type(exc).__name__}: {exc}")
            traceback.print_exc()
            continue

        bad = []
        for name, wanted in expect.items():
            want = wanted[LEVELS.index(level)]
            total += 1
            if name not in recorded:
                bad.append((name, want, "<not recorded>"))
            elif recorded[name] != want:
                bad.append((name, want, recorded[name]))

        failures.extend((level, *item) for item in bad)
        print(f"  {level:<8} {len(expect):>3} checks  "
              f"{'ok' if not bad else f'FAIL ({len(bad)})'}")
        for name, want, got in bad:
            print(f"      - {name}: expected {want!r}, got {got!r}")

    print()
    if failures:
        print(f"RESULT: {total - len(failures)}/{total} checks passed "
              f"— {len(failures)} mismatch(es)")
        return 1
    print(f"RESULT: {total}/{total} checks passed across {len(levels)} level(s)")
    return 0


def parse_levels(argv=None):
    """Accept explicit level names; unknown arguments are ignored."""
    argv = sys.argv[1:] if argv is None else argv
    chosen = [a for a in argv if a in LEVELS]
    return chosen or list(LEVELS)
