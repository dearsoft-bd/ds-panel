"""Team — an Admin whom the Super Admin allowed to "create users" (Role
Manager's can_manage_users) manages its own sub-admins here, e.g. a
support/editor account for its own site.

The ceiling is the creator itself: a team member is always role 'admin',
with at most the creator's own features and within the creator's own
site(s). That is checked here on every save AND re-applied on every
request by permissions.effective_access, so narrowing the creator later
immediately narrows its whole team too. An admin only ever sees and
manages the accounts it created directly.
"""
from functools import wraps

import bcrypt
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from .account import EMAIL_RE, _random_password
from .permissions import ALL, FEATURE_KEYS, FEATURES, SITE_SCOPED_FEATURES, parse_ids, session_features

bp = Blueprint("team", __name__)


def team_manager_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        cfg = current_app.config["PANEL_CONFIG"]
        if not session.get("user_id"):
            return redirect(cfg.login_url)
        if session.get("role") != "admin" or not session.get("can_manage_users"):
            flash("Your account can't manage users.", "error")
            return redirect(cfg.dashboard_url)
        return view(*args, **kwargs)

    return wrapped


def _my_limits():
    """(feature keys I may hand out, site rows I may hand out, am I site-restricted)."""
    mine = session_features(session)
    features = FEATURE_KEYS if mine == ALL else set(mine)
    restricted = bool(session.get("site_scope"))
    sites = g.db.execute("SELECT id, domain FROM sites ORDER BY domain").fetchall()
    if restricted:
        ids = parse_ids(session["site_scope"])
        sites = [s for s in sites if s["id"] in ids]
    return features, sites, restricted


def _parse_access(form):
    """Validated (permissions, site_scope, can_manage_users) for a team
    member from the submitted form, clamped to my own limits — or an error
    message."""
    my_features, my_sites, i_am_restricted = _my_limits()
    restricted = i_am_restricted or form.get("site_restricted") == "on"
    site_scope = ""
    if restricted:
        allowed_ids = {s["id"] for s in my_sites}
        chosen = parse_ids(",".join(form.getlist("site_scope"))) & allowed_ids
        if not chosen:
            return None, "Pick at least one of your sites for this account."
        site_scope = ",".join(str(i) for i in sorted(chosen))

    selected = {p for p in form.getlist("permissions") if p in my_features}
    if restricted:
        selected &= SITE_SCOPED_FEATURES
    if not selected:
        return None, "Pick at least one feature for this account."
    permissions = ALL if (not restricted and selected == FEATURE_KEYS) else ",".join(sorted(selected))
    can_manage_users = 1 if form.get("can_manage_users") == "on" else 0
    return (permissions, site_scope, can_manage_users), None


def _my_member(user_id: int):
    return g.db.execute(
        "SELECT * FROM users WHERE id = ? AND created_by = ?", (user_id, session.get("user_id"))
    ).fetchone()


@bp.route("/team")
@team_manager_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    my_features, my_sites, i_am_restricted = _my_limits()
    members = []
    for row in g.db.execute(
        "SELECT * FROM users WHERE created_by = ? ORDER BY created_at", (session.get("user_id"),)
    ).fetchall():
        m = dict(row)
        m["feature_set"] = FEATURE_KEYS if row["permissions"] == ALL else set((row["permissions"] or "").split(","))
        m["scope_set"] = parse_ids(row["site_scope"])
        m["restricted"] = bool(row["site_scope"])
        members.append(m)
    return render_template(
        "team.html",
        members=members,
        features=[(k, label) for k, label in FEATURES if k in my_features],
        site_scoped_features=SITE_SCOPED_FEATURES,
        sites=my_sites,
        i_am_restricted=i_am_restricted,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/team/add", methods=["POST"])
@team_manager_required
def add():
    cfg = current_app.config["PANEL_CONFIG"]
    back = f"{cfg.dashboard_url}team"
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    new_username = request.form.get("username", "").strip()
    custom_password = request.form.get("password", "").strip()

    if len(new_username) < 3:
        flash("Username must be at least 3 characters.", "error")
        return redirect(back)
    if email and not EMAIL_RE.match(email):
        flash("That doesn't look like a valid email.", "error")
        return redirect(back)
    if custom_password and len(custom_password) < 8:
        flash("Password must be at least 8 characters (or leave blank to auto-generate one).", "error")
        return redirect(back)
    if g.db.execute("SELECT 1 FROM users WHERE username = ?", (new_username,)).fetchone():
        flash(f"Username '{new_username}' is already taken.", "error")
        return redirect(back)

    access, error = _parse_access(request.form)
    if error:
        flash(error, "error")
        return redirect(back)
    permissions, site_scope, can_manage_users = access

    password = custom_password or _random_password()
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    g.db.execute(
        "INSERT INTO users (username, password_hash, full_name, email, role, permissions, site_scope, can_manage_users, created_by) "
        "VALUES (?, ?, ?, ?, 'admin', ?, ?, ?, ?)",
        (new_username, password_hash, full_name, email, permissions, site_scope, can_manage_users, session.get("user_id")),
    )
    g.db.commit()

    if custom_password:
        flash(f"User '{new_username}' created.", "success")
    else:
        flash(f"User '{new_username}' created with auto-generated password: {password} (shown once — save it now).", "success")
    return redirect(back)


@bp.route("/team/<int:user_id>/save", methods=["POST"])
@team_manager_required
def save(user_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    back = f"{cfg.dashboard_url}team"
    row = _my_member(user_id)
    if not row:
        flash("User not found.", "error")
        return redirect(back)
    access, error = _parse_access(request.form)
    if error:
        flash(error, "error")
        return redirect(back)
    g.db.execute(
        "UPDATE users SET permissions = ?, site_scope = ?, can_manage_users = ? WHERE id = ?",
        (*access, user_id),
    )
    g.db.commit()
    flash(f"Saved access for '{row['username']}'.", "success")
    return redirect(back)


@bp.route("/team/<int:user_id>/reset-password", methods=["POST"])
@team_manager_required
def reset_password(user_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    back = f"{cfg.dashboard_url}team"
    row = _my_member(user_id)
    if not row:
        flash("User not found.", "error")
        return redirect(back)
    password = _random_password()
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    g.db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    g.db.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (user_id,))
    g.db.commit()
    flash(f"Password for '{row['username']}' reset to: {password} (shown once — save it now).", "success")
    return redirect(back)


@bp.route("/team/<int:user_id>/delete", methods=["POST"])
@team_manager_required
def delete(user_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    back = f"{cfg.dashboard_url}team"
    row = _my_member(user_id)
    if not row:
        flash("User not found.", "error")
        return redirect(back)
    if g.db.execute("SELECT 1 FROM users WHERE created_by = ?", (user_id,)).fetchone():
        flash(f"'{row['username']}' still has team members of its own — they must be deleted first.", "error")
        return redirect(back)
    g.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    g.db.commit()
    flash(f"User '{row['username']}' deleted.", "success")
    return redirect(back)
