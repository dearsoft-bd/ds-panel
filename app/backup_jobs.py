"""Backup Jobs — the "smart dashboard" layer over the backup system: named,
independently-schedulable jobs (daily/weekly/monthly/a raw custom cron
expression), each producing either a full-server zip, a single site backup,
or a single database backup. Multiple jobs can run side by side. This sits
on top of (and writes into the same directories as) the simpler per-site/
per-database "Auto Backup" toggles already on the Sites/Databases pages —
it doesn't replace them, it adds the scheduling flexibility those don't have.

Execution (both the unattended cron poller and this page's "Run Now"
button) lives in backup_engine.py, not here — this module is routes only.
"""
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from . import backup_engine
from .security import login_required

bp = Blueprint("backup_jobs", __name__)

JOB_TYPES = {"full": "Full Server", "site": "Website", "database": "Database"}
SCHEDULE_TYPES = {"daily": "Daily", "weekly": "Weekly", "monthly": "Monthly", "custom": "Custom (cron expression)"}
WEEKDAYS = [(0, "Sunday"), (1, "Monday"), (2, "Tuesday"), (3, "Wednesday"), (4, "Thursday"), (5, "Friday"), (6, "Saturday")]


@bp.route("/backup-jobs")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    jobs = g.db.execute("SELECT * FROM backup_jobs ORDER BY created_at DESC").fetchall()
    sites = g.db.execute("SELECT domain FROM sites ORDER BY domain").fetchall()
    databases = g.db.execute("SELECT db_name FROM databases ORDER BY db_name").fetchall()

    return render_template(
        "backup_jobs.html",
        jobs=jobs,
        sites=sites,
        databases=databases,
        job_types=JOB_TYPES,
        schedule_types=SCHEDULE_TYPES,
        weekdays=WEEKDAYS,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/backup-jobs/create", methods=["POST"])
@login_required
def create():
    cfg = current_app.config["PANEL_CONFIG"]
    name = request.form.get("name", "").strip()
    job_type = request.form.get("job_type", "").strip()
    target = request.form.get("target", "").strip()
    schedule_type = request.form.get("schedule_type", "daily").strip()
    schedule_time = request.form.get("schedule_time", "02:30").strip()
    schedule_weekday = request.form.get("schedule_weekday", type=int) or 1
    schedule_day = request.form.get("schedule_day", type=int) or 1
    custom_cron = request.form.get("custom_cron", "").strip()
    retention = request.form.get("retention", type=int) or 7

    if not name:
        flash("Give the job a name.", "error")
        return redirect(f"{cfg.dashboard_url}backup-jobs")
    if job_type not in JOB_TYPES:
        flash("Unknown job type.", "error")
        return redirect(f"{cfg.dashboard_url}backup-jobs")
    if job_type != "full" and not target:
        flash("Choose a site or database for this job.", "error")
        return redirect(f"{cfg.dashboard_url}backup-jobs")
    if schedule_type not in SCHEDULE_TYPES:
        flash("Unknown schedule type.", "error")
        return redirect(f"{cfg.dashboard_url}backup-jobs")
    if schedule_type == "custom" and len(custom_cron.split()) != 5:
        flash("Custom schedule needs a 5-field cron expression (minute hour day month weekday).", "error")
        return redirect(f"{cfg.dashboard_url}backup-jobs")

    g.db.execute(
        "INSERT INTO backup_jobs (name, job_type, target, schedule_type, schedule_time, schedule_weekday, "
        "schedule_day, custom_cron, retention, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
        (name, job_type, "" if job_type == "full" else target, schedule_type, schedule_time,
         schedule_weekday, schedule_day, custom_cron, retention),
    )
    g.db.commit()

    flash(f"Backup job {name!r} created.", "success")
    return redirect(f"{cfg.dashboard_url}backup-jobs")


@bp.route("/backup-jobs/<int:job_id>/toggle", methods=["POST"])
@login_required
def toggle(job_id):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT enabled FROM backup_jobs WHERE id = ?", (job_id,)).fetchone()
    if row:
        g.db.execute("UPDATE backup_jobs SET enabled = ? WHERE id = ?", (0 if row["enabled"] else 1, job_id))
        g.db.commit()
    return redirect(f"{cfg.dashboard_url}backup-jobs")


@bp.route("/backup-jobs/<int:job_id>/delete", methods=["POST"])
@login_required
def delete(job_id):
    cfg = current_app.config["PANEL_CONFIG"]
    g.db.execute("DELETE FROM backup_jobs WHERE id = ?", (job_id,))
    g.db.commit()
    flash("Backup job deleted.", "success")
    return redirect(f"{cfg.dashboard_url}backup-jobs")


@bp.route("/backup-jobs/<int:job_id>/run-now", methods=["POST"])
@login_required
def run_now(job_id):
    cfg = current_app.config["PANEL_CONFIG"]
    job = g.db.execute("SELECT * FROM backup_jobs WHERE id = ?", (job_id,)).fetchone()
    if not job:
        flash("Job not found.", "error")
        return redirect(f"{cfg.dashboard_url}backup-jobs")

    success, detail = backup_engine.run_job(g.db, job)
    flash(f"{'Backup complete' if success else 'Backup failed'}: {detail}", "success" if success else "error")
    return redirect(f"{cfg.dashboard_url}backup-jobs")
