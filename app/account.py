"""Account — multi-user management. Four roles:
  - super_admin: full access, including managing every other account —
    creating/deleting users, changing roles, and locking a regular 'admin'
    down to specific sites (site_scope). Only ONE tier can do any of this;
    see security.super_admin_required. There is always at least one.
  - admin: full access to everything EXCEPT user management — unless a
    Super Admin has set a site_scope on this account, in which case it's
    locked to exactly those sites' Website + File Manager pages and
    nothing else at all (enforced in app/__init__.py's before_request
    hook and again, per-path, inside files.py/sites.py). This is the
    "give a client/junior admin their own site, nothing else" role.
  - viewer: can look at every page but is blocked from any write action
    (enforced once, globally, in app/__init__.py's before_request hook —
    not re-checked per route here).
  - custom: sees and can use only the feature areas explicitly checked for
    that account (FEATURES below) — read AND write within those areas,
    nothing at all outside them (the page isn't just read-only, it's not
    reachable). This is the cPanel-Reseller-ACL-style role for e.g. a
    junior dev who should only ever touch Files + Databases, or a
    support/billing person who should only see Backups.
Only the Super Admin can reach these routes at all (see
security.super_admin_required) — a regular admin, even an unrestricted
one, can no longer manage other accounts (otherwise a site-restricted
admin could simply un-restrict themselves).

FEATURES/BLUEPRINT_TO_FEATURE are the single source of truth for what a
"feature" is, used both here (to render the checkboxes) and in
app/__init__.py's before_request hook (to actually gate every request by
blueprint). Dashboard, Account (Super-Admin-only) and Monitor are
intentionally never gated by FEATURES — every logged-in user can always
reach them (Monitor's own content is still redacted for a site-restricted
admin — see monitor.py).
"""
import re
import secrets
import string

import bcrypt
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from .security import super_admin_required

bp = Blueprint("account", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ROLES = ["super_admin", "admin", "viewer", "custom"]

# (feature key, label shown in the UI)
FEATURES = [
    ("sites", "Website / Sites"),
    ("domains", "Domains"),
    ("files", "File Manager"),
    ("databases", "Databases"),
    ("backups", "Backups"),
    ("backup_jobs", "Backup Jobs"),
    ("docker", "Docker"),
    ("firewall", "Security / Firewall"),
    ("waf", "WAF"),
    ("mail_server", "Mail Server"),
    ("logs", "Logs"),
    ("dropshipping", "Dropshipping"),
    ("ssh_access", "SSH Access"),
    ("terminal", "Terminal"),
    ("ai", "AI Assistant"),
    ("cron", "Cron Jobs"),
    ("app_store", "App Store"),
    ("settings", "Settings"),
]
FEATURE_KEYS = {key for key, _ in FEATURES}

# Maps every gate-able blueprint to the feature key that controls it — several
# blueprints can share one checkbox (e.g. node_manager/disk_manager are part
# of the "Website / Sites" area, not separate toggles of their own).
BLUEPRINT_TO_FEATURE = {
    "sites": "sites", "node_manager": "sites", "disk_manager": "sites",
    "domains": "domains",
    "files": "files",
    "databases": "databases",
    "backups": "backups",
    "backup_jobs": "backup_jobs",
    "docker_manager": "docker",
    "firewall": "firewall", "tamper_proof": "firewall", "php_security": "firewall",
    "waf": "waf",
    "mail_server": "mail_server",
    "logs": "logs",
    "dropshipping": "dropshipping",
    "ssh_access": "ssh_access",
    "terminal": "terminal",
    "ai": "ai",
    "cron": "cron",
    "app_store": "app_store",
    "settings": "settings", "oauth_google": "settings",
}


def _parse_permissions(form) -> str:
    selected = [p for p in form.getlist("permissions") if p in FEATURE_KEYS]
    return ",".join(selected)


def _parse_site_scope(form, valid_site_ids: set) -> str:
    selected = [s for s in form.getlist("site_scope") if s.isdigit() and int(s) in valid_site_ids]
    return ",".join(selected)


def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@bp.route("/account")
@super_admin_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    rows = g.db.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    users = []
    for row in rows:
        u = dict(row)
        u["permission_set"] = set((row["permissions"] or "").split(",")) if row["permissions"] else set()
        u["site_scope_set"] = {int(x) for x in row["site_scope"].split(",") if x.strip().isdigit()} if row["site_scope"] else set()
        users.append(u)
    sites = g.db.execute("SELECT id, domain FROM sites ORDER BY domain").fetchall()
    return render_template(
        "account.html",
        users=users,
        roles=ROLES,
        features=FEATURES,
        sites=sites,
        current_user_id=session.get("user_id"),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/account/add", methods=["POST"])
@super_admin_required
def add_user():
    cfg = current_app.config["PANEL_CONFIG"]
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    new_username = request.form.get("username", "").strip()
    role = request.form.get("role", "viewer").strip()
    custom_password = request.form.get("password", "").strip()

    if not new_username or len(new_username) < 3:
        flash("Username must be at least 3 characters.", "error")
        return redirect(f"{cfg.dashboard_url}account")
    if email and not EMAIL_RE.match(email):
        flash("That doesn't look like a valid email.", "error")
        return redirect(f"{cfg.dashboard_url}account")
    if role not in ROLES:
        flash("Invalid role.", "error")
        return redirect(f"{cfg.dashboard_url}account")
    if custom_password and len(custom_password) < 8:
        flash("Password must be at least 8 characters (or leave blank to auto-generate one).", "error")
        return redirect(f"{cfg.dashboard_url}account")

    permissions = _parse_permissions(request.form) if role == "custom" else ""
    if role == "custom" and not permissions:
        flash("Pick at least one feature for a Custom role, or choose Admin/Viewer instead.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    site_scope = ""
    if role == "admin" and request.form.get("site_restricted") == "on":
        valid_site_ids = {r["id"] for r in g.db.execute("SELECT id FROM sites").fetchall()}
        site_scope = _parse_site_scope(request.form, valid_site_ids)
        if not site_scope:
            flash("Check 'Restrict to specific sites' and pick at least one site, or leave it unchecked.", "error")
            return redirect(f"{cfg.dashboard_url}account")

    existing = g.db.execute("SELECT id FROM users WHERE username = ?", (new_username,)).fetchone()
    if existing:
        flash(f"Username '{new_username}' is already taken.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    password = custom_password or _random_password()
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    g.db.execute(
        "INSERT INTO users (username, password_hash, full_name, email, role, permissions, site_scope) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (new_username, password_hash, full_name, email, role, permissions, site_scope),
    )
    g.db.commit()

    if not custom_password:
        flash(f"User '{new_username}' created with auto-generated password: {password} (shown once — save it now).", "success")
    else:
        flash(f"User '{new_username}' created.", "success")
    return redirect(f"{cfg.dashboard_url}account")


@bp.route("/account/<int:user_id>/delete", methods=["POST"])
@super_admin_required
def delete_user(user_id: int):
    cfg = current_app.config["PANEL_CONFIG"]

    if user_id == session.get("user_id"):
        flash("You can't delete your own account while logged in as it.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    row = g.db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        flash("User not found.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    if row["role"] == "super_admin":
        other_super_admins = g.db.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'super_admin' AND id != ?", (user_id,)
        ).fetchone()["n"]
        if other_super_admins == 0:
            flash("Can't delete the last Super Admin account — the panel would become unmanageable.", "error")
            return redirect(f"{cfg.dashboard_url}account")

    g.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    g.db.commit()
    flash(f"User '{row['username']}' deleted.", "success")
    return redirect(f"{cfg.dashboard_url}account")


@bp.route("/account/<int:user_id>/role", methods=["POST"])
@super_admin_required
def change_role(user_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    new_role = request.form.get("role", "").strip()

    if new_role not in ROLES:
        flash("Invalid role.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    row = g.db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        flash("User not found.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    if row["role"] == "super_admin" and new_role != "super_admin":
        other_super_admins = g.db.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'super_admin' AND id != ?", (user_id,)
        ).fetchone()["n"]
        if other_super_admins == 0:
            flash("Can't demote the last Super Admin — the panel would become unmanageable.", "error")
            return redirect(f"{cfg.dashboard_url}account")

    # The role dropdown alone has no checkboxes on it (those live in the
    # per-user permissions/site-scope panel below, submitted separately via
    # update_permissions/update_site_scope) — so switching to Custom or
    # Admin here just clears any stale permission/site list, leaving the
    # account with no extra access until the Super Admin checks boxes in
    # that panel and saves it. Not requiring a non-empty selection here is
    # what makes that two-step flow possible.
    permissions = _parse_permissions(request.form) if new_role == "custom" else ""
    site_scope = "" if new_role != "admin" else row["site_scope"]  # admin keeps its existing scope across other edits

    g.db.execute(
        "UPDATE users SET role = ?, permissions = ?, site_scope = ? WHERE id = ?",
        (new_role, permissions, site_scope, user_id),
    )
    g.db.commit()

    if user_id == session.get("user_id"):
        session["role"] = new_role
        session["permissions"] = permissions
        session["site_scope"] = site_scope

    if new_role == "custom":
        flash(f"Role updated for '{row['username']}' — now check the feature boxes below and click Save Permissions.", "success")
    elif new_role == "admin":
        flash(f"Role updated for '{row['username']}' — optionally restrict it to specific sites below.", "success")
    else:
        flash(f"Role updated for '{row['username']}'.", "success")
    return redirect(f"{cfg.dashboard_url}account")


@bp.route("/account/<int:user_id>/reset-password", methods=["POST"])
@super_admin_required
def reset_password(user_id: int):
    """Super Admin sets (or auto-generates) a new password for any account
    directly — no email/token round-trip needed, unlike the public Forgot
    Password flow. Useful when a user is locked out and can't wait on
    email, or has no email on file at all.
    """
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        flash("User not found.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    new_password = request.form.get("new_password", "").strip()
    if new_password and len(new_password) < 8:
        flash("Password must be at least 8 characters (or leave blank to auto-generate one).", "error")
        return redirect(f"{cfg.dashboard_url}account")

    password = new_password or _random_password()
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    g.db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    # Any outstanding email-based reset links for this account are burned —
    # an admin-set password should immediately invalidate an older token
    # sitting in someone's inbox.
    g.db.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (user_id,))
    g.db.commit()

    if user_id == session.get("user_id"):
        # Changing your OWN password this way still needs a fresh login —
        # same reasoning as Settings' own password change.
        session.clear()
        flash(f"Your password was reset to: {password} (shown once — save it now). Please log in again.", "success")
        return redirect(cfg.login_url)

    flash(f"Password for '{row['username']}' reset to: {password} (shown once — save it now).", "success")
    return redirect(f"{cfg.dashboard_url}account")


@bp.route("/account/<int:user_id>/site-scope", methods=["POST"])
@super_admin_required
def update_site_scope(user_id: int):
    """Lock (or unlock) a regular 'admin' account to specific sites only —
    the Super-Admin-managed equivalent of update_permissions for Custom
    roles. Leaving every checkbox unchecked removes the restriction
    entirely (the account goes back to full, unrestricted admin access) —
    that's a deliberate, explicit way out, not a trap.
    """
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        flash("User not found.", "error")
        return redirect(f"{cfg.dashboard_url}account")
    if row["role"] != "admin":
        flash("Site restriction only applies to the Admin role (Super Admin is never restricted).", "error")
        return redirect(f"{cfg.dashboard_url}account")

    valid_site_ids = {r["id"] for r in g.db.execute("SELECT id FROM sites").fetchall()}
    site_scope = _parse_site_scope(request.form, valid_site_ids)

    g.db.execute("UPDATE users SET site_scope = ? WHERE id = ?", (site_scope, user_id))
    g.db.commit()

    if user_id == session.get("user_id"):
        session["site_scope"] = site_scope

    if site_scope:
        flash(f"'{row['username']}' is now restricted to the selected site(s) only.", "success")
    else:
        flash(f"'{row['username']}' is no longer site-restricted — full admin access restored.", "success")
    return redirect(f"{cfg.dashboard_url}account")


@bp.route("/account/<int:user_id>/permissions", methods=["POST"])
@super_admin_required
def update_permissions(user_id: int):
    """Update just the feature checkboxes for an existing Custom-role user,
    without going through the role dropdown (used by the per-user
    "Edit permissions" panel on the Account page).
    """
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        flash("User not found.", "error")
        return redirect(f"{cfg.dashboard_url}account")
    if row["role"] != "custom":
        flash("Only Custom-role users have individual feature permissions to edit.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    permissions = _parse_permissions(request.form)
    if not permissions:
        flash("Pick at least one feature.", "error")
        return redirect(f"{cfg.dashboard_url}account")

    g.db.execute("UPDATE users SET permissions = ? WHERE id = ?", (permissions, user_id))
    g.db.commit()

    if user_id == session.get("user_id"):
        session["permissions"] = permissions

    flash(f"Permissions updated for '{row['username']}'.", "success")
    return redirect(f"{cfg.dashboard_url}account")
