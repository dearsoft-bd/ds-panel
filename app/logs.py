"""Logs viewer — read-only tail of a fixed, allow-listed set of system
logs (nginx, php-fpm, mysql, the panel's own service log). Never accepts
an arbitrary path from the request; the source is always looked up by key
against system_ops.log_sources().
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("logs", __name__)


@bp.route("/logs")
@login_required
def view_logs():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    sources = system_ops.log_sources()

    source_key = request.args.get("source", "nginx_error")
    if source_key not in sources:
        source_key = "nginx_error"
    lines = request.args.get("lines", 200, type=int) or 200
    grep = request.args.get("grep", "").strip()

    try:
        content = system_ops.tail_log(source_key, lines=lines, grep=grep)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        content = ""

    return render_template(
        "logs.html",
        sources=sources,
        source_key=source_key,
        lines=lines,
        grep=grep,
        content=content,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )
