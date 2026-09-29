#!/usr/bin/env python3
"""Runs every 5 minutes via cron (see install.sh), checks every backup_jobs
row's own schedule (daily/weekly/monthly/custom cron expression), and runs
whichever ones are due right now. The actual "what does running a job mean"
and "is it due" logic lives in app/backup_engine.py, shared with the
Flask "Run Now" button — this script is just the unattended trigger.
"""
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import backup_engine  # noqa: E402

DB_PATH = Path("/etc/ds-panel/panel.db")


def main() -> None:
    if not DB_PATH.is_file():
        print(f"[FAIL] panel database not found at {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        now = datetime.now()
        jobs = conn.execute("SELECT * FROM backup_jobs WHERE enabled = 1").fetchall()
        for job in jobs:
            if not backup_engine.is_due(job, now):
                continue
            success, detail = backup_engine.run_job(conn, job)
            status = "ok" if success else "FAIL"
            print(f"[{status}] backup job #{job['id']} ({job['name']!r}): {detail}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
