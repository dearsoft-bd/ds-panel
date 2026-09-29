"""Mail Server — Postfix + Dovecot virtual mailboxes. See
system_ops.py's module docstring on this feature for the important GCP/
cloud-provider port-25 caveat (also shown directly in the UI).
"""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("mail_server", __name__)


@bp.route("/mail")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    available = system_ops.mail_server_available()
    domains = system_ops.list_mail_domains() if available else []
    mailboxes = system_ops.list_mailboxes() if available else []

    return render_template(
        "mail_server.html",
        available=available,
        domains=domains,
        mailboxes=mailboxes,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/mail/domains/add", methods=["POST"])
@login_required
def add_domain():
    cfg = current_app.config["PANEL_CONFIG"]
    domain = request.form.get("domain", "").strip().lower()

    try:
        system_ops.add_mail_domain(domain)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}mail")

    flash(f"Mail domain '{domain}' added. Point its MX record at this server to receive mail.", "success")
    return redirect(f"{cfg.dashboard_url}mail")


@bp.route("/mail/domains/<domain>/delete", methods=["POST"])
@login_required
def delete_domain(domain: str):
    cfg = current_app.config["PANEL_CONFIG"]
    try:
        system_ops.remove_mail_domain(domain)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}mail")

    flash(f"Mail domain '{domain}' removed.", "success")
    return redirect(f"{cfg.dashboard_url}mail")


@bp.route("/mail/mailboxes/add", methods=["POST"])
@login_required
def add_mailbox():
    cfg = current_app.config["PANEL_CONFIG"]
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    try:
        system_ops.add_mailbox(email, password)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}mail")

    flash(f"Mailbox '{email}' created.", "success")
    return redirect(f"{cfg.dashboard_url}mail")


@bp.route("/mail/mailboxes/<path:email>/delete", methods=["POST"])
@login_required
def delete_mailbox(email: str):
    cfg = current_app.config["PANEL_CONFIG"]
    try:
        system_ops.remove_mailbox(email)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}mail")

    flash(f"Mailbox '{email}' removed.", "success")
    return redirect(f"{cfg.dashboard_url}mail")
