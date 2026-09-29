"""Database Management — Phase 4. Create/list/drop MySQL/MariaDB databases
and their dedicated user. The generated password is shown exactly once,
same rule as the panel's own admin password at install time — it's never
stored in plaintext, only used immediately to create the MySQL user.
"""
import secrets
import string

from flask import Blueprint, after_this_request, current_app, flash, g, redirect, render_template, request, send_file, session

from . import system_ops
from .security import login_required

bp = Blueprint("databases", __name__)


def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _known_users(db) -> set:
    """Every username this panel has created, whether via a database (the
    `databases` table) or standalone (the `db_users` table) — the single
    allow-list used everywhere a client-supplied username has to be
    checked against something real before touching MySQL.
    """
    from_dbs = {row["db_user"] for row in db.execute("SELECT DISTINCT db_user FROM databases").fetchall()}
    from_standalone = {row["username"] for row in db.execute("SELECT username FROM db_users").fetchall()}
    return from_dbs | from_standalone


@bp.route("/databases")
@login_required
def list_dbs():
    cfg = current_app.config["PANEL_CONFIG"]
    rows = g.db.execute("SELECT * FROM databases ORDER BY created_at DESC").fetchall()
    base = f"/{cfg.security_path}"
    shown_password = session.pop("last_db_password", None)
    shown_db = session.pop("last_db_name", None)
    shown_user = session.pop("last_db_user", None)
    pma_url = f"https://{request.host.split(':')[0]}:{cfg.pma_port}/" if cfg.pma_port else None
    existing_users = sorted(_known_users(g.db))

    # Every known user (whether they originated from a database row or a
    # standalone Create User), with a live count of how many databases
    # each is currently attached to — shown so "Delete" can explain why
    # it's blocked instead of just failing silently.
    db_counts = {
        row["db_user"]: row["n"]
        for row in g.db.execute("SELECT db_user, COUNT(*) AS n FROM databases GROUP BY db_user").fetchall()
    }
    standalone_created_at = {
        row["username"]: row["created_at"]
        for row in g.db.execute("SELECT username, created_at FROM db_users").fetchall()
    }
    first_db_created_at = {
        row["db_user"]: row["created_at"]
        for row in g.db.execute(
            "SELECT db_user, MIN(created_at) AS created_at FROM databases GROUP BY db_user"
        ).fetchall()
    }
    standalone_users = sorted(
        (
            {
                "username": username,
                "db_count": db_counts.get(username, 0),
                "created_at": standalone_created_at.get(username) or first_db_created_at.get(username, ""),
            }
            for username in existing_users
        ),
        key=lambda u: u["created_at"],
        reverse=True,
    )

    return render_template(
        "databases.html",
        databases=rows,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        shown_password=shown_password,
        shown_db=shown_db,
        shown_user=shown_user,
        pma_url=pma_url,
        existing_users=existing_users,
        standalone_users=standalone_users,
    )


@bp.route("/databases/users/add", methods=["POST"])
@login_required
def add_user():
    cfg = current_app.config["PANEL_CONFIG"]
    username = request.form.get("username", "").strip()
    custom_password = request.form.get("password", "").strip()

    if not system_ops.is_valid_db_identifier(username):
        flash("Username must start with a letter and contain only letters, digits, underscores.", "error")
        return redirect(f"{cfg.dashboard_url}databases")
    if custom_password and len(custom_password) < 8:
        flash("Password must be at least 8 characters (or leave it blank to auto-generate one).", "error")
        return redirect(f"{cfg.dashboard_url}databases")
    if username in _known_users(g.db):
        flash(f"User '{username}' already exists.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    password = custom_password or _random_password()
    try:
        system_ops.create_mysql_user_only(username, password)
    except system_ops.SystemOpError as e:
        flash(f"Failed to create user: {e}", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    g.db.execute("INSERT INTO db_users (username) VALUES (?)", (username,))
    g.db.commit()

    session["last_db_password"] = password
    session["last_db_name"] = None
    session["last_db_user"] = username
    flash(f"User '{username}' created (not yet attached to any database).", "success")
    return redirect(f"{cfg.dashboard_url}databases")


@bp.route("/databases/users/<username>/delete", methods=["POST"])
@login_required
def delete_user(username: str):
    cfg = current_app.config["PANEL_CONFIG"]
    if username not in _known_users(g.db):
        flash("User not found.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    still_used = g.db.execute(
        "SELECT COUNT(*) AS n FROM databases WHERE db_user = ?", (username,)
    ).fetchone()["n"]
    if still_used:
        flash(
            f"Can't delete '{username}' — still attached to {still_used} database(s). "
            "Reassign or delete those first.",
            "error",
        )
        return redirect(f"{cfg.dashboard_url}databases")

    try:
        system_ops.drop_mysql_user_only(username)
    except system_ops.SystemOpError as e:
        flash(f"Failed to delete user: {e}", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    g.db.execute("DELETE FROM db_users WHERE username = ?", (username,))
    g.db.commit()
    flash(f"User '{username}' deleted.", "success")
    return redirect(f"{cfg.dashboard_url}databases")


@bp.route("/databases/add", methods=["POST"])
@login_required
def add_db():
    cfg = current_app.config["PANEL_CONFIG"]
    db_name = request.form.get("db_name", "").strip()
    user_mode = request.form.get("user_mode", "new").strip()

    if not system_ops.is_valid_db_identifier(db_name):
        flash("Database name must start with a letter and contain only letters, digits, underscores.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    existing = g.db.execute("SELECT id FROM databases WHERE db_name = ?", (db_name,)).fetchone()
    if existing:
        flash(f"Database '{db_name}' already exists.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    if user_mode == "existing":
        db_user = request.form.get("existing_user", "").strip()
        # Defense in depth: only allow granting to a user this panel
        # itself already created (tracked in our own registry) — never an
        # arbitrary MySQL username typed into the request.
        known_users = _known_users(g.db)
        if db_user not in known_users:
            flash("Unknown user — pick one from the list.", "error")
            return redirect(f"{cfg.dashboard_url}databases")

        try:
            system_ops.grant_database_to_existing_user(db_name, db_user)
        except system_ops.SystemOpError as e:
            flash(f"Failed to create database: {e}", "error")
            return redirect(f"{cfg.dashboard_url}databases")

        g.db.execute("INSERT INTO databases (db_name, db_user) VALUES (?, ?)", (db_name, db_user))
        g.db.commit()
        flash(f"Database '{db_name}' created and granted to existing user '{db_user}' (same password as before).", "success")
        return redirect(f"{cfg.dashboard_url}databases")

    # user_mode == "new"
    db_user = request.form.get("db_user", "").strip()
    custom_password = request.form.get("db_password", "").strip()

    if not system_ops.is_valid_db_identifier(db_user):
        flash("Username must start with a letter and contain only letters, digits, underscores.", "error")
        return redirect(f"{cfg.dashboard_url}databases")
    if custom_password and len(custom_password) < 8:
        flash("Password must be at least 8 characters (or leave it blank to auto-generate one).", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    password = custom_password or _random_password()
    try:
        system_ops.create_database(db_name, db_user, password)
    except system_ops.SystemOpError as e:
        flash(f"Failed to create database: {e}", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    g.db.execute("INSERT INTO databases (db_name, db_user) VALUES (?, ?)", (db_name, db_user))
    g.db.commit()

    # Shown once on the next page load via flashed session values, then
    # popped — same "never persisted in plaintext" rule as the admin
    # password generated at install time.
    session["last_db_password"] = password
    session["last_db_name"] = db_name
    session["last_db_user"] = db_user
    flash(f"Database '{db_name}' created.", "success")
    return redirect(f"{cfg.dashboard_url}databases")


@bp.route("/databases/<int:db_id>/edit", methods=["POST"])
@login_required
def edit_db(db_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM databases WHERE id = ?", (db_id,)).fetchone()
    if not row:
        flash("Database not found.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    new_user = request.form.get("new_user", "").strip() or row["db_user"]
    new_password = request.form.get("new_password", "").strip()

    known_users = _known_users(g.db)
    if new_user not in known_users:
        flash("Unknown user — pick one from the list.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    try:
        if new_user != row["db_user"]:
            system_ops.reassign_database_user(row["db_name"], row["db_user"], new_user)
            g.db.execute("UPDATE databases SET db_user = ? WHERE id = ?", (new_user, db_id))
            g.db.commit()
        if new_password:
            if len(new_password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return redirect(f"{cfg.dashboard_url}databases")
            system_ops.set_user_password(new_user, new_password)
    except system_ops.SystemOpError as e:
        flash(f"Failed to update database: {e}", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    if new_password:
        # Same "shown once" pattern as creating a new database.
        session["last_db_password"] = new_password
        session["last_db_name"] = row["db_name"]
        session["last_db_user"] = new_user
        flash(f"Database '{row['db_name']}' updated.", "success")
    else:
        flash(f"Database '{row['db_name']}' now owned by user '{new_user}'.", "success")
    return redirect(f"{cfg.dashboard_url}databases")


@bp.route("/databases/<int:db_id>/auto-backup", methods=["POST"])
@login_required
def set_auto_backup(db_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM databases WHERE id = ?", (db_id,)).fetchone()
    if not row:
        flash("Database not found.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    enabled = 1 if request.form.get("enabled") == "on" else 0
    retention = request.form.get("retention", 7, type=int) or 7
    retention = max(1, min(retention, 90))

    g.db.execute(
        "UPDATE databases SET auto_backup_enabled = ?, backup_retention = ? WHERE id = ?",
        (enabled, retention, db_id),
    )
    g.db.commit()
    flash(
        f"Auto Backup {'enabled' if enabled else 'disabled'} for {row['db_name']}"
        + (f" (keeping last {retention})." if enabled else "."),
        "success",
    )
    return redirect(f"{cfg.dashboard_url}databases")


@bp.route("/databases/<int:db_id>/backup")
@login_required
def backup_db(db_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM databases WHERE id = ?", (db_id,)).fetchone()
    if not row:
        flash("Database not found.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    try:
        backup_path = system_ops.backup_database(row["db_name"])
    except system_ops.SystemOpError as e:
        flash(f"Backup failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    @after_this_request
    def _cleanup(response):
        backup_path.unlink(missing_ok=True)
        return response

    return send_file(backup_path, as_attachment=True, download_name=backup_path.name)


@bp.route("/databases/<int:db_id>/delete", methods=["POST"])
@login_required
def delete_db(db_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM databases WHERE id = ?", (db_id,)).fetchone()
    if not row:
        flash("Database not found.", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    # If this user is also granted on other databases, only drop this one
    # database — dropping the MySQL user itself would cut off access to
    # every other database sharing it.
    other_dbs_with_same_user = g.db.execute(
        "SELECT COUNT(*) AS n FROM databases WHERE db_user = ? AND id != ?",
        (row["db_user"], db_id),
    ).fetchone()["n"]
    is_standalone_user = g.db.execute(
        "SELECT 1 FROM db_users WHERE username = ?", (row["db_user"],)
    ).fetchone() is not None

    try:
        system_ops.drop_database(
            row["db_name"], row["db_user"],
            drop_user=other_dbs_with_same_user == 0 and not is_standalone_user,
        )
    except system_ops.SystemOpError as e:
        flash(f"Failed to drop database: {e}", "error")
        return redirect(f"{cfg.dashboard_url}databases")

    g.db.execute("DELETE FROM databases WHERE id = ?", (db_id,))
    g.db.commit()
    flash(f"Database '{row['db_name']}' dropped.", "success")
    return redirect(f"{cfg.dashboard_url}databases")
