"""SSH Access — view/add/revoke public keys in a system user's
authorized_keys. Deliberately does not touch sshd_config (port, root
login, password auth) — see system_ops.py's module docstring on this
feature for why that's out of scope on purpose.
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("ssh_access", __name__)


@bp.route("/ssh-access")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    users = system_ops.list_ssh_users()
    selected_user = request.args.get("user", users[0]["username"] if users else "")
    keys = []
    if selected_user:
        try:
            keys = system_ops.list_ssh_keys(selected_user)
        except system_ops.SystemOpError as e:
            flash(str(e), "error")

    return render_template(
        "ssh_access.html",
        users=users,
        selected_user=selected_user,
        keys=keys,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/ssh-access/add", methods=["POST"])
@login_required
def add_key():
    cfg = current_app.config["PANEL_CONFIG"]
    target_user = request.form.get("user", "").strip()
    key_line = request.form.get("key", "").strip()
    label = request.form.get("label", "").strip()

    if label and len(key_line.split()) == 2:  # type + key only, no comment yet
        key_line = f"{key_line} {label}"

    try:
        system_ops.add_ssh_key(target_user, key_line)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}ssh-access?user={target_user}")

    flash(f"Key added for {target_user}.", "success")
    return redirect(f"{cfg.dashboard_url}ssh-access?user={target_user}")


@bp.route("/ssh-access/delete", methods=["POST"])
@login_required
def delete_key():
    cfg = current_app.config["PANEL_CONFIG"]
    target_user = request.form.get("user", "").strip()
    key_index = request.form.get("index", -1, type=int)

    try:
        system_ops.delete_ssh_key(target_user, key_index)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}ssh-access?user={target_user}")

    flash(f"Key removed for {target_user}.", "success")
    return redirect(f"{cfg.dashboard_url}ssh-access?user={target_user}")
