"""Settings — change the admin account's username/password, configure
Google OAuth login, and a read-only panel info card.
"""
import json
import re

import bcrypt
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("settings", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@bp.route("/settings")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    row = g.db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    suggested_redirect_uri = f"https://{request.host}/{cfg.security_path}/auth/google/callback"

    return render_template(
        "settings.html",
        current_username=row["username"] if row else "",
        panel_port=cfg.port,
        security_path=cfg.security_path,
        pma_port=cfg.pma_port,
        google_oauth_enabled=cfg.google_oauth_enabled,
        google_client_id=cfg.google_client_id,
        google_client_secret=cfg.google_client_secret,
        google_allowed_email=cfg.google_allowed_email,
        google_redirect_uri=cfg.google_redirect_uri or suggested_redirect_uri,
        ai_provider=cfg.ai_provider,
        ai_api_key=cfg.ai_api_key,
        ai_model=cfg.ai_model,
        panel_domain=cfg.panel_domain,
        smtp_host=cfg.smtp_host,
        smtp_port=cfg.smtp_port,
        smtp_username=cfg.smtp_username,
        smtp_password=cfg.smtp_password,
        smtp_from_address=cfg.smtp_from_address,
        smtp_use_tls=cfg.smtp_use_tls,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/settings/ai", methods=["POST"])
@login_required
def update_ai():
    cfg = current_app.config["PANEL_CONFIG"]
    provider = request.form.get("provider", "").strip()
    api_key = request.form.get("api_key", "").strip()
    model = request.form.get("model", "").strip()

    if provider and provider not in ("claude", "openai"):
        flash("Unknown AI provider.", "error")
        return redirect(f"{cfg.dashboard_url}settings")

    with open(cfg.config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    data["ai"] = {"provider": provider, "api_key": api_key, "model": model}

    with open(cfg.config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    flash(
        "AI Assistant settings saved. Restart the panel service for this to take effect: "
        "sudo systemctl restart ds-panel",
        "success",
    )
    return redirect(f"{cfg.dashboard_url}settings")


@bp.route("/settings/domain", methods=["POST"])
@login_required
def update_domain():
    cfg = current_app.config["PANEL_CONFIG"]
    domain = request.form.get("domain", "").strip().lower()
    admin_email = request.form.get("admin_email", "").strip()
    issue_ssl = request.form.get("issue_ssl") == "on"

    if domain:
        try:
            system_ops.set_panel_domain(domain, cfg.port)
            if issue_ssl:
                if not admin_email:
                    flash("An email is required to issue an SSL certificate.", "error")
                    return redirect(f"{cfg.dashboard_url}settings")
                system_ops.issue_certificate(domain, admin_email)
        except system_ops.SystemOpError as e:
            flash(f"Couldn't set up {domain}: {e}", "error")
            return redirect(f"{cfg.dashboard_url}settings")
    elif cfg.panel_domain:
        try:
            system_ops.remove_panel_domain(cfg.panel_domain)
        except system_ops.SystemOpError as e:
            flash(str(e), "error")
            return redirect(f"{cfg.dashboard_url}settings")

    with open(cfg.config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["panel_domain"] = domain
    with open(cfg.config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    if domain:
        flash(
            f"Panel is now reachable at http{'s' if issue_ssl else ''}://{domain}/{cfg.security_path}/login "
            "(make sure the domain's DNS already points at this server). Restart the panel service to update this page's display.",
            "success",
        )
    else:
        flash("Custom domain removed.", "success")
    return redirect(f"{cfg.dashboard_url}settings")


@bp.route("/settings/oauth", methods=["POST"])
@login_required
def update_oauth():
    cfg = current_app.config["PANEL_CONFIG"]
    client_id = request.form.get("client_id", "").strip()
    client_secret = request.form.get("client_secret", "").strip()
    allowed_email = request.form.get("allowed_email", "").strip().lower()
    redirect_uri = request.form.get("redirect_uri", "").strip()

    if allowed_email and not EMAIL_RE.match(allowed_email):
        flash("That doesn't look like a valid email.", "error")
        return redirect(f"{cfg.dashboard_url}settings")

    with open(cfg.config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    data["oauth"] = {
        "google_client_id": client_id,
        "google_client_secret": client_secret,
        "google_allowed_email": allowed_email,
        "google_redirect_uri": redirect_uri,
    }

    with open(cfg.config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    flash(
        "Google OAuth settings saved. Restart the panel service for this to take effect: "
        "sudo systemctl restart ds-panel",
        "success",
    )
    return redirect(f"{cfg.dashboard_url}settings")


@bp.route("/settings/smtp", methods=["POST"])
@login_required
def update_smtp():
    cfg = current_app.config["PANEL_CONFIG"]
    host = request.form.get("smtp_host", "").strip()
    port = request.form.get("smtp_port", "").strip()
    username = request.form.get("smtp_username", "").strip()
    password = request.form.get("smtp_password", "")
    from_address = request.form.get("smtp_from_address", "").strip()
    use_tls = request.form.get("smtp_use_tls") == "on"

    if from_address and not EMAIL_RE.match(from_address):
        flash("That doesn't look like a valid 'From' email address.", "error")
        return redirect(f"{cfg.dashboard_url}settings")

    with open(cfg.config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing = data.get("smtp", {})
    # A blank password field means "keep the existing one" (same pattern as
    # not showing a saved password back in the form) — otherwise saving the
    # form again with the password field left empty would wipe it out.
    data["smtp"] = {
        "host": host,
        "port": int(port) if port.isdigit() else 587,
        "username": username,
        "password": password if password else existing.get("password", ""),
        "from_address": from_address,
        "use_tls": use_tls,
    }

    with open(cfg.config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    flash(
        "SMTP settings saved (used for Forgot Password reset emails). "
        "Restart the panel service for this to take effect: sudo systemctl restart ds-panel",
        "success",
    )
    return redirect(f"{cfg.dashboard_url}settings")


@bp.route("/settings/account", methods=["POST"])
@login_required
def update_account():
    cfg = current_app.config["PANEL_CONFIG"]
    current_password = request.form.get("current_password", "")
    new_username = request.form.get("new_username", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    row = g.db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not row or not bcrypt.checkpw(current_password.encode("utf-8"), row["password_hash"].encode("utf-8")):
        flash("Current password is incorrect.", "error")
        return redirect(f"{cfg.dashboard_url}settings")

    if new_password:
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "error")
            return redirect(f"{cfg.dashboard_url}settings")
        if new_password != confirm_password:
            flash("New password and confirmation don't match.", "error")
            return redirect(f"{cfg.dashboard_url}settings")

    updates = []
    params = []
    if new_username and new_username != row["username"]:
        existing = g.db.execute(
            "SELECT id FROM users WHERE username = ? AND id != ?", (new_username, row["id"])
        ).fetchone()
        if existing:
            flash(f"Username '{new_username}' is already taken.", "error")
            return redirect(f"{cfg.dashboard_url}settings")
        updates.append("username = ?")
        params.append(new_username)

    if new_password:
        new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        updates.append("password_hash = ?")
        params.append(new_hash)

    if not updates:
        flash("Nothing to update.", "error")
        return redirect(f"{cfg.dashboard_url}settings")

    params.append(row["id"])
    g.db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
    g.db.commit()

    if new_username and new_username != row["username"]:
        session["username"] = new_username

    if new_password:
        # Password changed — force re-login everywhere, this session included,
        # same reasoning as any "change password" flow: an old session token
        # shouldn't keep working past the point the credential it was issued
        # for has changed.
        session.clear()
        flash("Password updated. Please log in again.", "success")
        return redirect(cfg.login_url)

    flash("Account updated.", "success")
    return redirect(f"{cfg.dashboard_url}settings")
