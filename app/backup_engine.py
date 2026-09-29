"""Shared Backup Job execution/scheduling logic — used by both the "Run Now"
button in the Flask app (backup_jobs.py) and the standalone cron poller
(scripts/run_backup_jobs.py), so there's exactly one implementation of what
running a job does and what "due right now" means. Kept dependency-free of
Flask so the standalone script doesn't need an app context.
"""
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from . import system_ops


def _rotate(target_dir: Path, retention: int) -> None:
    backups = sorted(target_dir.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[retention:]:
        old.unlink(missing_ok=True)


def run_job(conn, job) -> tuple[bool, str]:
    """Executes one backup_jobs row right now, regardless of its schedule.
    Returns (success, detail) and records the result on the job row + in
    backup_log either way.
    """
    job_type = job["job_type"]
    target = job["target"]
    retention = job["retention"] or 7

    try:
        if job_type == "site":
            produced = system_ops.backup_site(target)
            target_dir = system_ops.SCHEDULED_BACKUP_DIR / "sites" / target
        elif job_type == "database":
            produced = system_ops.backup_database(target)
            target_dir = system_ops.SCHEDULED_BACKUP_DIR / "databases" / target
        elif job_type == "full":
            site_domains = [r["domain"] for r in conn.execute("SELECT domain FROM sites").fetchall()]
            db_names = [r["db_name"] for r in conn.execute("SELECT db_name FROM databases").fetchall()]
            produced = system_ops.backup_full_server(site_domains, db_names)
            target_dir = system_ops.SCHEDULED_BACKUP_DIR / "full" / "server"
        else:
            raise system_ops.SystemOpError(f"Unknown job type: {job_type!r}")

        target_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(produced), str(target_dir / produced.name))
        _rotate(target_dir, retention)
        detail = produced.name
        success = True
    except system_ops.SystemOpError as e:
        detail = str(e)
        success = False

    # Naive server-local time, deliberately — matches the existing fixed
    # "30 2 * * *" scheduled-backup cron entry, which crontab also
    # interprets in the system's local timezone, not UTC.
    now_iso = datetime.now().isoformat()
    conn.execute(
        "UPDATE backup_jobs SET last_run_at = ?, last_status = ? WHERE id = ?",
        (now_iso, "success" if success else "failed", job["id"]),
    )
    conn.execute(
        "INSERT INTO backup_log (action, target_type, target_name, status, detail) VALUES (?, ?, ?, ?, ?)",
        ("backup_job", job_type, target or "server", "success" if success else "failed", detail),
    )
    conn.commit()
    return success, detail


def _cron_field_matches(field: str, value: int) -> bool:
    if field == "*":
        return True
    for part in field.split(","):
        if part.startswith("*/"):
            step = int(part[2:])
            if value % step == 0:
                return True
        elif "-" in part:
            lo, hi = part.split("-")
            if int(lo) <= value <= int(hi):
                return True
        elif part.isdigit() and int(part) == value:
            return True
    return False


def cron_matches(expr: str, now: datetime) -> bool:
    """Minimal 5-field cron matcher (minute hour day month weekday) — enough
    for the common patterns an admin would actually type, not a full
    croniter reimplementation. weekday uses cron's own 0=Sunday convention.
    """
    fields = expr.split()
    if len(fields) != 5:
        return False
    minute, hour, day, month, weekday = fields
    cron_weekday = (now.isoweekday()) % 7  # Python Mon=1..Sun=7 -> cron Sun=0..Sat=6
    return (
        _cron_field_matches(minute, now.minute)
        and _cron_field_matches(hour, now.hour)
        and _cron_field_matches(day, now.day)
        and _cron_field_matches(month, now.month)
        and _cron_field_matches(weekday, cron_weekday)
    )


def is_due(job, now: datetime) -> bool:
    if not job["enabled"]:
        return False

    schedule_type = job["schedule_type"]
    if schedule_type == "custom":
        due = cron_matches(job["custom_cron"], now)
    else:
        try:
            sched_hour, sched_minute = (int(p) for p in job["schedule_time"].split(":"))
        except ValueError:
            return False
        # Bucketed to 5 minutes since the poller itself only runs every 5
        # minutes (see install.sh) — an exact-minute match would silently
        # never fire if the admin picked a minute the poller doesn't land on.
        time_matches = now.hour == sched_hour and (now.minute // 5) == (sched_minute // 5)
        if schedule_type == "daily":
            due = time_matches
        elif schedule_type == "weekly":
            due = time_matches and now.isoweekday() % 7 == job["schedule_weekday"]
        elif schedule_type == "monthly":
            due = time_matches and now.day == job["schedule_day"]
        else:
            due = False

    if not due:
        return False

    if job["last_run_at"]:
        last_run = datetime.fromisoformat(job["last_run_at"])
        if (now - last_run) < timedelta(minutes=4):
            return False

    return True
