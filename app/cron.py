"""Cron — Phase 5. Thin UI over the real crontab (root's own, for v1 — see
system_ops.py). Not a custom scheduler.
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request

from . import system_ops
from .security import login_required

bp = Blueprint("cron", __name__)


@bp.route("/cron")
@login_required
def list_jobs():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    try:
        jobs = system_ops.list_cron_jobs()
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        jobs = []
    return render_template(
        "cron.html",
        jobs=list(enumerate(jobs)),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
    )


@bp.route("/cron/add", methods=["POST"])
@login_required
def add_job():
    cfg = current_app.config["PANEL_CONFIG"]
    schedule = request.form.get("schedule", "")
    command = request.form.get("command", "")

    try:
        system_ops.add_cron_job(schedule, command)
        flash("Cron job added.", "success")
    except system_ops.SystemOpError as e:
        flash(f"Failed: {e}", "error")
    return redirect(f"{cfg.dashboard_url}cron")


@bp.route("/cron/<int:index>/delete", methods=["POST"])
@login_required
def delete_job(index: int):
    cfg = current_app.config["PANEL_CONFIG"]
    try:
        system_ops.delete_cron_job(index)
        flash("Cron job removed.", "success")
    except system_ops.SystemOpError as e:
        flash(f"Failed: {e}", "error")
    return redirect(f"{cfg.dashboard_url}cron")
