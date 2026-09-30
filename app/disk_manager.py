"""Disk Mount Manager — v1 safe subset (confirmed with the user): list
disks/partitions and mount/unmount an already-partitioned block device on
demand. Deliberately never touches /etc/fstab, so nothing here can leave a
server unable to boot — mounts made this way don't survive a reboot.
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from . import disk_view, system_ops
from .security import login_required

bp = Blueprint("disk_manager", __name__)


@bp.before_request
def _hide_real_disks():
    # Listing block devices would reveal the real disk sizes that a
    # "custom" disk display (Role Manager) exists to hide.
    if disk_view.is_custom():
        flash("Disk management isn't available for your account.", "error")
        return redirect(current_app.config["PANEL_CONFIG"].dashboard_url)
    return None


@bp.route("/disk-manager")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    return render_template(
        "disk_manager.html",
        devices=system_ops.list_block_devices(),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/disk-manager/mount", methods=["POST"])
@login_required
def mount():
    cfg = current_app.config["PANEL_CONFIG"]
    name = request.form.get("name", "").strip()

    try:
        mount_point = system_ops.mount_device(name)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}disk-manager")

    flash(f"Mounted /dev/{name} at {mount_point}. This does not survive a reboot.", "success")
    return redirect(f"{cfg.dashboard_url}disk-manager")


@bp.route("/disk-manager/unmount", methods=["POST"])
@login_required
def unmount():
    cfg = current_app.config["PANEL_CONFIG"]
    name = request.form.get("name", "").strip()

    try:
        system_ops.unmount_device(name)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}disk-manager")

    flash(f"Unmounted /dev/{name}.", "success")
    return redirect(f"{cfg.dashboard_url}disk-manager")
