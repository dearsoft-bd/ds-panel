"""Firewall — Phase 6 (partial). A thin wrapper over ufw: allow/deny a
port. Not a request-inspecting WAF — see project plan for why that's
explicitly out of scope for v1.

The panel's own port and SSH (22) are protected from being closed via this
UI — locking yourself out of both the panel and SSH in the same action
would require a console/recovery-mode fix with no easy undo.
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request

from . import system_ops
from .security import login_required

bp = Blueprint("firewall", __name__)

PROTECTED_PORTS = {22}  # SSH — never let the UI close this


@bp.route("/firewall")
@login_required
def status():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    try:
        rules = system_ops.list_firewall_rules()
    except system_ops.SystemOpError as e:
        rules = []
        flash(f"Could not read firewall status: {e}", "error")
    return render_template(
        "firewall.html",
        rules=rules,
        panel_port=cfg.port,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
    )


@bp.route("/firewall/allow", methods=["POST"])
@login_required
def allow():
    cfg = current_app.config["PANEL_CONFIG"]
    try:
        port = int(request.form.get("port", ""))
    except ValueError:
        flash("Invalid port.", "error")
        return redirect(f"{cfg.dashboard_url}firewall")

    try:
        system_ops.allow_port(port)
        flash(f"Port {port} allowed.", "success")
    except system_ops.SystemOpError as e:
        flash(f"Failed: {e}", "error")
    return redirect(f"{cfg.dashboard_url}firewall")


@bp.route("/firewall/deny", methods=["POST"])
@login_required
def deny():
    cfg = current_app.config["PANEL_CONFIG"]
    try:
        port = int(request.form.get("port", ""))
    except ValueError:
        flash("Invalid port.", "error")
        return redirect(f"{cfg.dashboard_url}firewall")

    if port in PROTECTED_PORTS or port == cfg.port:
        flash(f"Port {port} is protected (SSH or the panel itself) and can't be closed here.", "error")
        return redirect(f"{cfg.dashboard_url}firewall")

    try:
        system_ops.deny_port(port)
        flash(f"Port {port} rule removed.", "success")
    except system_ops.SystemOpError as e:
        flash(f"Failed: {e}", "error")
    return redirect(f"{cfg.dashboard_url}firewall")
