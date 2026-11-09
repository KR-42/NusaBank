"""Run every verification module and summarise the result.

Usage:
    python tests/run_all.py                # all modules, all four levels
    python tests/run_all.py hard           # only the `hard` level
    python tests/run_all.py verify_admin   # only matching module(s)

Exits non-zero if any check disagrees with its expectation, so the suite can
gate a change to the lab.
"""

import pathlib
import sys
import time
import traceback

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness import LEVELS, parse_levels  # noqa: E402

MODULES = [
    "verify_transactions",
    "verify_uploads_claims",
    "verify_ssrf_api",
    "verify_admin",
    "verify_public_pages",
]


def main():
    levels = parse_levels()
    wanted = [a for a in sys.argv[1:] if a not in LEVELS]
    chosen = [m for m in MODULES if not wanted or any(w in m for w in wanted)]

    print(f"NusaBank verification suite - levels: {', '.join(levels)}")
    results = []
    started = time.time()

    for name in chosen:
        try:
            module = __import__(name)
        except Exception as exc:  # noqa: BLE001
            print(f"\n=== {name} ===\n  IMPORT FAILED: {exc}")
            traceback.print_exc()
            results.append((name, 1, 0, 0))
            continue

        started_module = time.time()
        code = module.run_module(module.TITLE, module.run, module.EXPECT, levels)
        elapsed = time.time() - started_module
        results.append((name, code, len(module.EXPECT), elapsed))

    print("\n" + "=" * 60)
    print("SUMMARY")
    failed = 0
    for name, code, checks, elapsed in results:
        status = "PASS" if code == 0 else "FAIL"
        failed += code != 0
        print(f"  {status}  {name:<26} {checks:>3} checks  {elapsed:5.1f}s")
    print(f"\n{len(results) - failed}/{len(results)} modules passed "
          f"in {time.time() - started:.1f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
