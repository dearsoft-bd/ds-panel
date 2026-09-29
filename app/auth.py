"""Login/logout, plus Forgot Password (email-based reset). Mounted under the
random security-entrance path (e.g. /a1b2c3d4/login) chosen at install time —
see app/config.py — so the login form isn't sitting at a guessable /login or
/admin URL for scanners to find.
"""
import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText

import bcrypt
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired

from .security import is_locked_out, record_attempt

bp = Blueprint("auth", __name__)

RESET_TOKEN_VALID_MINUTES = 30


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


def _client_ip() -> str:
    # Trust X-Forwarded-For only if the panel is deliberately placed behind
    # a reverse proxy the admin controls; for a directly-exposed panel (the
    # default for v1) request.remote_addr is the real client IP and cannot
    # be spoofed by the request itself.
    return request.remote_addr or "unknown"


@bp.route("/login", methods=["GET", "POST"])
def login():
    cfg = current_app.config["PANEL_CONFIG"]
    form = LoginForm()
    ip = _client_ip()

    if is_locked_out(ip):
        flash("Too many failed attempts. Try again in a few minutes.", "error")
        return render_template(
            "login.html", form=form, locked_out=True,
            google_oauth_enabled=cfg.google_oauth_enabled,
            google_login_url=f"/{cfg.security_path}/auth/google",
            forgot_password_url=f"/{cfg.security_path}/forgot-password",
        )

    if form.validate_on_submit():
        row = current_app.config["get_db"]().execute(
            "SELECT id, username, password_hash, role, permissions, site_scope FROM users WHERE username = ?",
            (form.username.data,),
        ).fetchone()

        valid = row is not None and bcrypt.checkpw(
            form.password.data.encode("utf-8"), row["password_hash"].encode("utf-8")
        )

        record_attempt(ip, succeeded=valid)

        if valid:
            session.clear()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            session["permissions"] = row["permissions"] or ""
            session["site_scope"] = row["site_scope"] or ""
            return redirect(cfg.dashboard_url)

        flash("Invalid username or password.", "error")

    return render_template(
        "login.html", form=form, locked_out=False,
        google_oauth_enabled=cfg.google_oauth_enabled,
        google_login_url=f"/{cfg.security_path}/auth/google",
        forgot_password_url=f"/{cfg.security_path}/forgot-password",
    )


@bp.route("/logout", methods=["POST"])
def logout():
    cfg = current_app.config["PANEL_CONFIG"]
    session.clear()
    return redirect(cfg.login_url)


# ---- Forgot Password (email-based reset) -----------------------------------
# Deliberately doesn't reveal whether a username/email exists — the flash
# message is identical either way, so this can't be used to enumerate valid
# panel accounts from the outside.
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _send_reset_email(cfg, to_address: str, username: str, reset_url: str) -> bool:
    if not cfg.smtp_enabled:
        return False
    body = (
        f"Hi {username},\n\n"
        f"A password reset was requested for your DS Panel account.\n\n"
        f"Reset your password here (link expires in {RESET_TOKEN_VALID_MINUTES} minutes):\n"
        f"{reset_url}\n\n"
        f"If you didn't request this, you can safely ignore this email — "
        f"your password will not be changed.\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = "DS Panel — Password Reset"
    msg["From"] = cfg.smtp_from_address
    msg["To"] = to_address

    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as server:
            if cfg.smtp_use_tls:
                server.starttls()
            if cfg.smtp_username:
                server.login(cfg.smtp_username, cfg.smtp_password)
            server.sendmail(cfg.smtp_from_address, [to_address], msg.as_string())
        return True
    except (smtplib.SMTPException, OSError):
        return False


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    cfg = current_app.config["PANEL_CONFIG"]
    db = current_app.config["get_db"]()

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        ip = _client_ip()

        # Same lockout counter as login — a password-reset form is just as
        # good an oracle for brute-forcing/enumerating accounts as the login
        # form itself if it isn't rate-limited the same way.
        if is_locked_out(ip):
            flash("Too many attempts. Try again in a few minutes.", "error")
            return render_template("forgot_password.html", base_url=f"/{cfg.security_path}")

        row = db.execute(
            "SELECT id, username, email FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower()),
        ).fetchone()
        record_attempt(ip, succeeded=row is not None)

        if row and row["email"]:
            token = secrets.token_urlsafe(32)
            expires_at = (datetime.utcnow() + timedelta(minutes=RESET_TOKEN_VALID_MINUTES)).isoformat(
                sep=" ", timespec="seconds"
            )
            db.execute(
                "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                (row["id"], _hash_token(token), expires_at),
            )
            db.commit()
            reset_url = f"https://{request.host}/{cfg.security_path}/reset-password/{token}"
            if not _send_reset_email(cfg, row["email"], row["username"], reset_url):
                # SMTP not configured, or the send itself failed — this is an
                # admin-facing infrastructure problem, not something to leak
                # to whoever's on the login page (could be an attacker probing
                # for valid usernames), so it's only ever logged/flashed here
                # in a way that still gives away nothing account-specific.
                current_app.logger.warning("Password reset email failed to send (SMTP not configured or send error).")

        flash(
            "If an account with that username/email exists and has an email on file, "
            "a password reset link has been sent.",
            "success",
        )
        return redirect(cfg.login_url)

    return render_template("forgot_password.html", base_url=f"/{cfg.security_path}")


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    cfg = current_app.config["PANEL_CONFIG"]
    db = current_app.config["get_db"]()
    token_hash = _hash_token(token)
    now = datetime.utcnow().isoformat(sep=" ", timespec="seconds")

    reset_row = db.execute(
        "SELECT * FROM password_resets WHERE token_hash = ? AND used = 0 AND expires_at >= ?",
        (token_hash, now),
    ).fetchone()

    if not reset_row:
        flash("This password reset link is invalid or has expired. Request a new one.", "error")
        return redirect(f"/{cfg.security_path}/forgot-password")

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(new_password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", token=token, base_url=f"/{cfg.security_path}")
        if new_password != confirm_password:
            flash("Passwords don't match.", "error")
            return render_template("reset_password.html", token=token, base_url=f"/{cfg.security_path}")

        new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, reset_row["user_id"]))
        # Every other outstanding reset token for this user is burned too —
        # otherwise an older, still-valid link (e.g. from an inbox someone
        # else can also read) would keep working after this reset.
        db.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (reset_row["user_id"],))
        db.commit()

        flash("Password reset. You can now log in with your new password.", "success")
        return redirect(cfg.login_url)

    return render_template("reset_password.html", token=token, base_url=f"/{cfg.security_path}")
