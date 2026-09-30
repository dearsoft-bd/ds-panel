"""Backups browser — lists every persisted scheduled backup (Sites +
Databases), lets the admin download/restore/delete one, and keeps an
action log. This is the read/manage side of the scheduled Auto Backup
system configured from the Sites/Databases pages; scripts/run_scheduled_
backups.py is what actually produces the files this page lists.
"""
from datetime import datetime, timezone

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, send_file, session

from . import system_ops
from .security import login_required, restricted_site_domains

bp = Blueprint("backups", __name__)


@bp.before_request
def _enforce_backup_site_scope():
    # A site-restricted admin only ever sees/acts on its own sites' backups —
    # never database backups (databases aren't tied to a site) and never the
    # shared actions log.
    domains = restricted_site_domains()
    if domains is None or request.endpoint == "backups.list_backups":
        return None
    cfg = current_app.config["PANEL_CONFIG"]
    source = request.form if request.method == "POST" else request.args
    if request.endpoint == "backups.clear_log" or source.get("type") != "sites" or source.get("name") not in domains:
        flash("You can only manage your own site's backups.", "error")
        return redirect(f"{cfg.dashboard_url}backups")
    return None


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _log(db, action: str, target_type: str, target_name: str, status: str, detail: str = "") -> None:
    db.execute(
        "INSERT INTO backup_log (action, target_type, target_name, status, detail) VALUES (?, ?, ?, ?, ?)",
        (action, target_type, target_name, status, detail),
    )
    db.commit()


@bp.route("/backups")
@login_required
def list_backups():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    raw = system_ops.list_backups()
    domains = restricted_site_domains()
    if domains is not None:
        raw = [b for b in raw if b["target_type"] == "sites" and b["target_name"] in domains]

    # Grouped by (type, target) so each card in the template lists every
    # available date for one site/database, newest first — building this
    # here keeps the template a plain loop instead of needing a Jinja
    # groupby over a dict.
    groups = {}
    for b in raw:
        key = (b["target_type"], b["target_name"])
        groups.setdefault(key, []).append({
            **b,
            "size_human": _human_size(b["size"]),
            "date": datetime.fromtimestamp(b["mtime"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        })
    backup_groups = [
        {"target_type": t, "target_name": n, "entries": items}
        for (t, n), items in sorted(groups.items())
    ]

    log_rows = g.db.execute(
        "SELECT * FROM backup_log ORDER BY id DESC LIMIT 50"
    ).fetchall()
    if domains is not None:
        log_rows = [r for r in log_rows if r["target_type"] == "sites" and r["target_name"] in domains]

    return render_template(
        "backups.html",
        backup_groups=backup_groups,
        log_rows=log_rows,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/backups/download")
@login_required
def download_backup():
    cfg = current_app.config["PANEL_CONFIG"]
    target_type = request.args.get("type", "")
    target_name = request.args.get("name", "")
    filename = request.args.get("file", "")

    try:
        path = system_ops.get_backup_file_path(target_type, target_name, filename)
    except system_ops.SystemOpError as e:
        flash(str(e), "error")
        return redirect(f"{cfg.dashboard_url}backups")

    return send_file(path, as_attachment=True, download_name=path.name)


@bp.route("/backups/restore", methods=["POST"])
@login_required
def restore_backup():
    cfg = current_app.config["PANEL_CONFIG"]
    target_type = request.form.get("type", "")
    target_name = request.form.get("name", "")
    filename = request.form.get("file", "")

    try:
        if target_type == "sites":
            system_ops.restore_site_backup(target_name, filename)
        elif target_type == "databases":
            system_ops.restore_database_backup(target_name, filename)
        else:
            raise system_ops.SystemOpError(f"Invalid backup type: {target_type!r}")
    except system_ops.SystemOpError as e:
        _log(g.db, "restore", target_type, target_name, "failed", str(e))
        flash(f"Restore failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}backups")

    _log(g.db, "restore", target_type, target_name, "success", filename)
    flash(f"Restored {target_name} from {filename}.", "success")
    return redirect(f"{cfg.dashboard_url}backups")


@bp.route("/backups/clear-log", methods=["POST"])
@login_required
def clear_log():
    cfg = current_app.config["PANEL_CONFIG"]
    g.db.execute("DELETE FROM backup_log")
    g.db.commit()
    flash("Actions log cleared.", "success")
    return redirect(f"{cfg.dashboard_url}backups")


@bp.route("/backups/delete", methods=["POST"])
@login_required
def delete_backup():
    cfg = current_app.config["PANEL_CONFIG"]
    target_type = request.form.get("type", "")
    target_name = request.form.get("name", "")
    filename = request.form.get("file", "")

    try:
        system_ops.delete_backup_file(target_type, target_name, filename)
    except system_ops.SystemOpError as e:
        _log(g.db, "delete", target_type, target_name, "failed", str(e))
        flash(f"Delete failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}backups")

    _log(g.db, "delete", target_type, target_name, "success", filename)
    flash(f"Deleted backup {filename}.", "success")
    return redirect(f"{cfg.dashboard_url}backups")
