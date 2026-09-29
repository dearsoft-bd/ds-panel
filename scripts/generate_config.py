#!/usr/bin/env python3
"""Run once at install time (called by install.sh). Generates:
  - a random high port and a random security-entrance URL path
  - a Flask session secret key
  - a self-signed TLS cert (replace with a real cert/Let's Encrypt later —
    the panel's own login page needs HTTPS from the very first boot, before
    any domain/cert management feature exists to get it a real one)
  - the admin user row (bcrypt-hashed password), printing the generated
    password to the installer's terminal exactly once — it is never stored
    in plaintext anywhere, including this script's own memory beyond the
    point it's hashed and printed.

Usage:
    python3 generate_config.py --config-dir /etc/ds-panel [--username admin]
    python3 generate_config.py --config-dir /etc/ds-panel --extra-admins john,mary

--extra-admins creates additional full-admin accounts (comma-separated
usernames) alongside the first one, each with its own random password —
for teams that want more than one admin login from the very first boot,
instead of creating them one at a time later from the Account page.

For local development against this repo (no root, no /etc write access),
point --config-dir at a local folder, e.g. ../instance.
"""
import argparse
import json
import secrets
import string
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bcrypt  # noqa: E402

from app.db import get_connection, init_db  # noqa: E402

RESERVED_LOW_PORTS = range(0, 10000)  # avoid common/well-known ports entirely


def random_port() -> int:
    while True:
        port = secrets.randbelow(65535 - 10000) + 10000
        if port not in RESERVED_LOW_PORTS:
            return port


def random_security_path() -> str:
    return secrets.token_hex(4)  # 8 hex chars, e.g. "a1b2c3d4"


def random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-nodes",
            "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-days", "825",
            "-subj", "/CN=ds-panel",
        ],
        check=True,
        capture_output=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", required=True, type=Path)
    parser.add_argument("--username", default="admin")
    parser.add_argument(
        "--extra-admins", default="",
        help="Comma-separated usernames for additional admin accounts, e.g. 'john,mary'",
    )
    args = parser.parse_args()

    config_dir: Path = args.config_dir
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.json"

    if config_path.exists():
        print(f"Config already exists at {config_path} — refusing to overwrite.", file=sys.stderr)
        print("Delete it manually first if you really want to regenerate.", file=sys.stderr)
        sys.exit(1)

    ssl_dir = config_dir / "ssl"
    cert_path = ssl_dir / "panel.crt"
    key_path = ssl_dir / "panel.key"
    generate_self_signed_cert(cert_path, key_path)

    db_path = config_dir / "panel.db"

    config = {
        "secret_key": secrets.token_hex(32),
        "security_path": random_security_path(),
        "port": random_port(),
        "host": "0.0.0.0",
        "ssl_cert": str(cert_path),
        "ssl_key": str(key_path),
        "db_path": str(db_path),
        "install_id": secrets.token_hex(16),
    }

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    init_db(db_path)

    # First admin, plus any --extra-admins usernames — all created as full
    # 'admin' role accounts, each with its own independently generated
    # password. Blank/duplicate entries are dropped rather than erroring
    # the whole install over a typo'd trailing comma.
    extra_usernames = [u.strip() for u in args.extra_admins.split(",") if u.strip()]
    usernames = [args.username] + [u for u in extra_usernames if u != args.username]
    seen = set()
    admins = []
    for username in usernames:
        if username in seen:
            continue
        seen.add(username)
        admins.append((username, random_password()))

    conn = get_connection(db_path)
    try:
        for i, (username, password) in enumerate(admins):
            # The very first account is the Super Admin — the only role that
            # can manage other accounts, promote/demote roles, or lock a
            # regular Admin down to specific sites (see app/account.py).
            # Every --extra-admins username is a regular (unrestricted)
            # 'admin' that the Super Admin can later restrict if wanted.
            role = "super_admin" if i == 0 else "admin"
            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role),
            )
        conn.commit()
    finally:
        conn.close()

    print("=" * 60)
    print("DS Panel - first-run credentials (shown once, save now)")
    print("=" * 60)
    print(f"URL: https://<this-server-ip>:{config['port']}/{config['security_path']}/login")
    for i, (username, password) in enumerate(admins):
        print(f"Username: {username} ({'Super Admin' if i == 0 else 'Admin'})")
        print(f"Password: {password}")
        print("-" * 60)
    print("=" * 60)


if __name__ == "__main__":
    main()
