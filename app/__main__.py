"""WSGI entry point and development server.

Run locally:      python -m app --host=127.0.0.1:8080
Run in Docker:    python -m app --host=0.0.0.0:8080   (port is published to 127.0.0.1)
"""

import argparse
import os
import sys

from . import create_app

app = create_app()


def _warn():
    banner = r"""
  _   _                 ____              _
 | \ | |_   _ ___  __ _| __ )  __ _ _ __ | | __
 |  \| | | | / __|/ _` |  _ \ / _` | '_ \| |/ /
 | |\  | |_| \__ \ (_| | |_) | (_| | | | |   <
 |_| \_|\__,_|___/\__,_|____/ \__,_|_| |_|_|\_\

  !! LAB PENTEST — APLIKASI INI SENGAJA DIBUAT RENTAN !!
  Jangan pernah meng-expose ke internet. Jalankan hanya di
  lingkungan lokal / Docker terisolasi. Semua data adalah fiktif.
"""
    print(banner)
    print(f"  LAB_LEVEL aktif : {os.environ.get('LAB_LEVEL', 'easy')}")
    print(f"  Peringatan      : http://127.0.0.1:8080 (loopback only)\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="NusaBank lab server")
    parser.add_argument("--host", default="127.0.0.1:8080")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)

    host, _, port = args.host.partition(":")
    port = int(port or 8080)

    if not os.path.exists(app.config["DB_PATH"]):
        print(f"[!] Database tidak ditemukan di {app.config['DB_PATH']}")
        print("    Jalankan:  python scripts/setup.py\n")
        sys.exit(1)

    _warn()
    app.run(host=host, port=port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
