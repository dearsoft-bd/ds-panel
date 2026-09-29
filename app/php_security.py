"""PHP Code Security — disables a fixed, well-known set of dangerous PHP
functions (exec/shell_exec/proc_open/etc, see system_ops.DANGEROUS_PHP_FUNCTIONS)
at the php.ini level, per PHP-FPM version. Off by default; applies to every
site running that PHP version once turned on.
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("php_security", __name__)


@bp.route("/php-security")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    status = {v: system_ops.get_php_security_status(v) for v in system_ops.ALLOWED_PHP_VERSIONS}

    return render_template(
        "php_security.html",
        status=status,
        dangerous_functions=system_ops.DANGEROUS_PHP_FUNCTIONS,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/php-security/toggle", methods=["POST"])
@login_required
def toggle():
    cfg = current_app.config["PANEL_CONFIG"]
    php_version = request.form.get("php_version", "").strip()
    enable = request.form.get("enabled") == "on"

    try:
        system_ops.set_php_security_enabled(php_version, enable)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}php-security")

    flash(f"PHP Code Security {'enabled' if enable else 'disabled'} for PHP {php_version}.", "success")
    return redirect(f"{cfg.dashboard_url}php-security")
