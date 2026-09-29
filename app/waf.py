"""WAF — ModSecurity (nginx) + OWASP Core Rule Set, global on/off and
Detection-Only/Blocking mode toggle, plus a recent-events view. See
system_ops.py's module docstring on this feature for the DetectionOnly-
by-default safety reasoning.
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("waf", __name__)


@bp.route("/waf")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    installed = system_ops.waf_installed()
    status = system_ops.get_waf_status() if installed else {"enabled": False, "mode": "DetectionOnly"}
    events = system_ops.waf_recent_events() if installed and status["enabled"] else ""

    return render_template(
        "waf.html",
        installed=installed,
        status=status,
        events=events,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/waf/toggle", methods=["POST"])
@login_required
def toggle():
    cfg = current_app.config["PANEL_CONFIG"]
    enabled = request.form.get("enabled") == "on"

    try:
        system_ops.set_waf_enabled(enabled)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}waf")

    flash(f"WAF {'enabled' if enabled else 'disabled'}.", "success")
    return redirect(f"{cfg.dashboard_url}waf")


@bp.route("/waf/install", methods=["POST"])
@login_required
def install():
    cfg = current_app.config["PANEL_CONFIG"]
    try:
        system_ops.install_waf()
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}waf")

    flash("WAF installed. It's off by default — enable it below when you're ready.", "success")
    return redirect(f"{cfg.dashboard_url}waf")


@bp.route("/waf/mode", methods=["POST"])
@login_required
def set_mode():
    cfg = current_app.config["PANEL_CONFIG"]
    mode = request.form.get("mode", "").strip()

    try:
        system_ops.set_waf_mode(mode)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}waf")

    flash(f"WAF mode set to {mode}.", "success")
    return redirect(f"{cfg.dashboard_url}waf")
