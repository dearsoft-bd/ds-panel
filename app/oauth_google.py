"""Google OAuth login — a second way into the SAME single admin account,
not open registration. Only the one email configured as
oauth.google_allowed_email in config.json may ever be granted a session
this way; every other Google account is rejected regardless of how the
Google consent flow itself resolves the sign-in.
"""
import secrets

import requests
from flask import Blueprint, current_app, flash, g, redirect, request, session, url_for

from .security import record_attempt

bp = Blueprint("oauth_google", __name__)

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


@bp.route("/auth/google")
def start():
    cfg = current_app.config["PANEL_CONFIG"]
    if not cfg.google_oauth_enabled:
        flash("Google login is not configured on this server.", "error")
        return redirect(cfg.login_url)

    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state

    params = {
        "client_id": cfg.google_client_id,
        "redirect_uri": cfg.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    return redirect(f"{AUTH_URL}?{query}")


@bp.route("/auth/google/callback")
def callback():
    cfg = current_app.config["PANEL_CONFIG"]
    ip = request.remote_addr or "unknown"

    error = request.args.get("error")
    if error:
        flash("Google sign-in was cancelled or failed.", "error")
        return redirect(cfg.login_url)

    state = request.args.get("state", "")
    if not state or state != session.pop("oauth_state", None):
        flash("OAuth state mismatch — please try signing in again.", "error")
        return redirect(cfg.login_url)

    code = request.args.get("code", "")
    if not code:
        flash("Google sign-in failed (no code returned).", "error")
        return redirect(cfg.login_url)

    try:
        token_resp = requests.post(
            TOKEN_URL,
            data={
                "code": code,
                "client_id": cfg.google_client_id,
                "client_secret": cfg.google_client_secret,
                "redirect_uri": cfg.google_redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=10,
        )
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]

        userinfo_resp = requests.get(
            USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()
    except requests.RequestException:
        flash("Could not reach Google to complete sign-in. Try again.", "error")
        return redirect(cfg.login_url)

    email = str(userinfo.get("email", "")).strip().lower()
    email_verified = bool(userinfo.get("email_verified"))

    allowed = email_verified and email and email == cfg.google_allowed_email
    record_attempt(ip, succeeded=allowed)

    if not allowed:
        flash("This Google account is not authorized for this panel.", "error")
        return redirect(cfg.login_url)

    # Prefer the local account whose own email matches the Google account
    # that just signed in; fall back to the first admin for installs from
    # before per-user email existed (email defaults to '' otherwise).
    row = g.db.execute("SELECT id, username, role, permissions, site_scope FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        row = g.db.execute(
            "SELECT id, username, role, permissions, site_scope FROM users WHERE role IN ('super_admin', 'admin') ORDER BY id LIMIT 1"
        ).fetchone()
    if not row:
        flash("No local admin account exists to attach this login to.", "error")
        return redirect(cfg.login_url)

    session.clear()
    session["user_id"] = row["id"]
    session["username"] = row["username"]
    session["role"] = row["role"]
    session["permissions"] = row["permissions"] or ""
    session["site_scope"] = row["site_scope"] or ""
    return redirect(cfg.dashboard_url)
