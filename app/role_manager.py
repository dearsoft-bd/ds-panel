"""Role Manager — the Super Admin's control over what every Admin account
can do: which features it holds, which site(s) it is locked to, whether it
may create further admins under itself (team.py), and what disk capacity
its dashboard shows.

Disk display "custom" is a deliberate security measure: the account sees a
Super-Admin-chosen total and only its OWN usage, never the server's real
size or free space — see disk_view.py.
"""
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from . import disk_view
from .permissions import ALL, DISK_DISPLAY_MODES, FEATURE_KEYS, FEATURES, SITE_SCOPED_FEATURES, parse_ids
from .security import super_admin_required

bp = Blueprint("role_manager", __name__)


@bp.route("/roles")
@super_admin_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    names = {r["id"]: r["username"] for r in g.db.execute("SELECT id, username FROM users").fetchall()}
    admins = []
    for row in g.db.execute("SELECT * FROM users WHERE role = 'admin' ORDER BY created_at").fetchall():
        a = dict(row)
        a["all_features"] = row["permissions"] == ALL
        a["feature_set"] = FEATURE_KEYS if a["all_features"] else set((row["permissions"] or "").split(","))
        a["scope_set"] = parse_ids(row["site_scope"])
        a["restricted"] = bool(row["site_scope"])
        a["created_by_name"] = names.get(row["created_by"]) if row["created_by"] else None
        admins.append(a)
    return render_template(
        "role_manager.html",
        admins=admins,
        features=FEATURES,
        site_scoped_features=SITE_SCOPED_FEATURES,
        sites=g.db.execute("SELECT id, domain FROM sites ORDER BY domain").fetchall(),
        real_disk=disk_view.real_disk(),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/roles/<int:user_id>/save", methods=["POST"])
@super_admin_required
def save(user_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    back = f"{cfg.dashboard_url}roles"
    row = g.db.execute("SELECT * FROM users WHERE id = ? AND role = 'admin'", (user_id,)).fetchone()
    if not row:
        flash("Admin account not found.", "error")
        return redirect(back)

    restricted = request.form.get("site_restricted") == "on"
    site_scope = ""
    if restricted:
        valid = {r["id"] for r in g.db.execute("SELECT id FROM sites").fetchall()}
        site_scope = ",".join(str(i) for i in sorted(parse_ids(",".join(request.form.getlist("site_scope"))) & valid))
        if not site_scope:
            flash("Pick at least one site to restrict to, or untick 'Restrict to specific sites'.", "error")
            return redirect(back)

    selected = {p for p in request.form.getlist("permissions") if p in FEATURE_KEYS}
    dropped = set()
    if restricted:
        dropped = selected - SITE_SCOPED_FEATURES
        selected &= SITE_SCOPED_FEATURES
        permissions = ",".join(sorted(selected))
    else:
        permissions = ALL if selected == FEATURE_KEYS else ",".join(sorted(selected))

    disk_display = request.form.get("disk_display", "real")
    if disk_display not in DISK_DISPLAY_MODES:
        disk_display = "real"
    disk_quota_gb = request.form.get("disk_quota_gb", type=int) or 0
    if disk_display == "custom" and disk_quota_gb <= 0:
        flash("Enter the disk size (GB) this account should see, or choose 'Real'.", "error")
        return redirect(back)

    can_manage_users = 1 if request.form.get("can_manage_users") == "on" else 0

    g.db.execute(
        "UPDATE users SET permissions = ?, site_scope = ?, can_manage_users = ?, disk_display = ?, disk_quota_gb = ? WHERE id = ?",
        (permissions, site_scope, can_manage_users, disk_display, max(disk_quota_gb, 0), user_id),
    )
    g.db.commit()

    message = f"Saved access for '{row['username']}'."
    if dropped:
        labels = ", ".join(label for key, label in FEATURES if key in dropped)
        message += f" Not given (server-wide/root-level, can't be combined with a site restriction): {labels}."
    flash(message, "success")
    return redirect(back)
