"""Node.js Version Manager — install/switch system-wide Node.js major
versions via "n" (tj/n), for sites that need something other than the LTS
version install.sh sets up by default. See system_ops.py's own section
docstring for the pm2-restart-on-switch reasoning.
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("node_manager", __name__)


@bp.route("/node-manager")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    installed = system_ops.node_manager_installed()
    current_version = system_ops.current_node_version() if installed else None
    installed_versions = system_ops.installed_node_versions() if installed else []

    return render_template(
        "node_manager.html",
        installed=installed,
        current_version=current_version,
        installed_versions=installed_versions,
        node_versions=system_ops.NODE_VERSIONS,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/node-manager/switch", methods=["POST"])
@login_required
def switch():
    cfg = current_app.config["PANEL_CONFIG"]
    version = request.form.get("version", "").strip()

    try:
        system_ops.switch_node_version(version)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}node-manager")

    flash(f"Switched system Node.js to v{version}. pm2 was told to reload its own daemon.", "success")
    return redirect(f"{cfg.dashboard_url}node-manager")
