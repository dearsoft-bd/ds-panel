"""Login rate-limiting/lockout and the `login_required` guard.

Lockout policy: 5 failed attempts from the same IP within 15 minutes blocks
further attempts from that IP for the rest of the window. Deliberately
per-IP (not per-username) so a single attacker can't lock a real admin out
by repeatedly failing that admin's username, and so distributed guessing
across many usernames from one IP is still throttled.
"""
from datetime import datetime, timedelta
from functools import wraps

from flask import current_app, g, redirect, session

MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 15


def record_attempt(ip_address: str, succeeded: bool) -> None:
    g.db.execute(
        "INSERT INTO login_attempts (ip_address, succeeded) VALUES (?, ?)",
        (ip_address, 1 if succeeded else 0),
    )
    g.db.commit()


def is_locked_out(ip_address: str) -> bool:
    cutoff = (datetime.utcnow() - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)).isoformat(
        sep=" ", timespec="seconds"
    )
    row = g.db.execute(
        """
        SELECT COUNT(*) AS failures
        FROM login_attempts
        WHERE ip_address = ?
          AND succeeded = 0
          AND attempted_at >= ?
        """,
        (ip_address, cutoff),
    ).fetchone()
    return (row["failures"] or 0) >= MAX_ATTEMPTS


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            cfg = current_app.config["PANEL_CONFIG"]
            return redirect(cfg.login_url)
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    """For routes only the 'admin' or 'super_admin' role may use."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        cfg = current_app.config["PANEL_CONFIG"]
        if not session.get("user_id"):
            return redirect(cfg.login_url)
        if session.get("role") not in ("admin", "super_admin"):
            from flask import flash
            flash("Only admins can do that.", "error")
            return redirect(cfg.dashboard_url)
        return view(*args, **kwargs)

    return wrapped


def super_admin_required(view):
    """For routes only the 'super_admin' role may use — user management
    itself (creating accounts, changing roles, locking an 'admin' account
    down to specific sites). A regular 'admin' — even an unrestricted one —
    can no longer reach these: letting any admin manage other accounts
    would let a site-restricted admin simply un-restrict themselves.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        cfg = current_app.config["PANEL_CONFIG"]
        if not session.get("user_id"):
            return redirect(cfg.login_url)
        if session.get("role") != "super_admin":
            from flask import flash
            flash("Only the Super Admin can do that.", "error")
            return redirect(cfg.dashboard_url)
        return view(*args, **kwargs)

    return wrapped


def restricted_site_ids():
    """None = this session is not site-restricted (super_admin, an
    unrestricted admin, viewer, or custom). A set (possibly empty) = this
    session is an 'admin' a Super Admin has locked to exactly these site
    IDs — see account.py's site_scope.
    """
    if session.get("role") != "admin" or not session.get("site_scope"):
        return None
    return {int(x) for x in session["site_scope"].split(",") if x.strip().isdigit()}
