"""Docker — basic container management: list, start/stop/restart, remove,
view logs. A thin UI over the real `docker` CLI (system_ops.py), not a
reimplementation of Docker itself. Named docker_manager (not docker) so
this module never shadows the real `docker` Python package if it's ever
installed in the venv.
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("docker_manager", __name__)


@bp.route("/docker")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    available = system_ops.docker_available()
    containers = []
    if available:
        try:
            containers = system_ops.list_containers()
        except system_ops.SystemOpError as e:
            flash(str(e), "error")

    return render_template(
        "docker.html",
        available=available,
        containers=containers,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/docker/<container_id>/action", methods=["POST"])
@login_required
def action(container_id: str):
    cfg = current_app.config["PANEL_CONFIG"]
    act = request.form.get("action", "")

    try:
        system_ops.container_action(container_id, act)
    except system_ops.SystemOpError as e:
        flash(f"Action failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}docker")

    flash(f"Container {act}ed.", "success")
    return redirect(f"{cfg.dashboard_url}docker")


@bp.route("/docker/<container_id>/remove", methods=["POST"])
@login_required
def remove(container_id: str):
    cfg = current_app.config["PANEL_CONFIG"]
    try:
        system_ops.remove_container(container_id)
    except system_ops.SystemOpError as e:
        flash(f"Remove failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}docker")

    flash("Container removed.", "success")
    return redirect(f"{cfg.dashboard_url}docker")


@bp.route("/docker/<container_id>/logs")
@login_required
def logs(container_id: str):
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    try:
        log_text = system_ops.container_logs(container_id)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}docker")

    return render_template(
        "docker_logs.html",
        container_id=container_id,
        log_text=log_text,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )
