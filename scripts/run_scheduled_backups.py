#!/usr/bin/env python3
"""Runs the daily backup sweep for every site/database with auto-backup
enabled. Invoked by a single cron entry that install.sh installs — never
run interactively, and never touches anything not explicitly opted in via
the panel's Sites/Databases pages.

Kept as a standalone script (not a Flask route) deliberately: a scheduled
backup shouldn't depend on the web process being healthy to run, and this
is the same "runs as root, only through system_ops.py" trust model as the
rest of the app.
"""
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import system_ops  # noqa: E402

DB_PATH = Path("/etc/ds-panel/panel.db")
SCHEDULED_DIR = system_ops.BACKUP_DIR / "scheduled"


def _rotate(target_dir: Path, retention: int) -> None:
    backups = sorted(target_dir.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[retention:]:
        old.unlink(missing_ok=True)


def _log(conn: sqlite3.Connection, target_type: str, target_name: str, status: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO backup_log (action, target_type, target_name, status, detail) VALUES (?, ?, ?, ?, ?)",
        ("scheduled_backup", target_type, target_name, status, detail),
    )
    conn.commit()


def backup_sites(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT * FROM sites WHERE auto_backup_enabled = 1").fetchall()
    for row in rows:
        target_dir = SCHEDULED_DIR / "sites" / row["domain"]
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            produced = system_ops.backup_site(row["domain"])
            shutil.move(str(produced), str(target_dir / produced.name))
            _rotate(target_dir, row["backup_retention"] or 7)
            _log(conn, "sites", row["domain"], "success", produced.name)
            print(f"[ok] site backup: {row['domain']}")
        except system_ops.SystemOpError as e:
            _log(conn, "sites", row["domain"], "failed", str(e))
            print(f"[FAIL] site backup {row['domain']}: {e}", file=sys.stderr)


def backup_databases(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT * FROM databases WHERE auto_backup_enabled = 1").fetchall()
    for row in rows:
        target_dir = SCHEDULED_DIR / "databases" / row["db_name"]
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            produced = system_ops.backup_database(row["db_name"])
            shutil.move(str(produced), str(target_dir / produced.name))
            _rotate(target_dir, row["backup_retention"] or 7)
            _log(conn, "databases", row["db_name"], "success", produced.name)
            print(f"[ok] database backup: {row['db_name']}")
        except system_ops.SystemOpError as e:
            _log(conn, "databases", row["db_name"], "failed", str(e))
            print(f"[FAIL] database backup {row['db_name']}: {e}", file=sys.stderr)


def main() -> None:
    if not DB_PATH.is_file():
        print(f"[FAIL] panel database not found at {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    SCHEDULED_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        print(f"=== Scheduled backup run: {datetime.now(timezone.utc).isoformat()} ===")
        backup_sites(conn)
        backup_databases(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
