"""Dashboard — quick-stat cards linking into each feature area."""
from flask import Blueprint, current_app, g, jsonify, render_template, session

from . import disk_view, system_ops
from .security import login_required, restricted_site_ids
from .terminal import is_terminal_enabled

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    scope_ids = restricted_site_ids()
    site_restricted = scope_ids is not None

    # A site-restricted admin sees full hardware/server stats below (CPU,
    # RAM, disk, hostname, uptime — none of that identifies another
    # tenant), but every count that would otherwise reveal how many OTHER
    # sites/databases/mailboxes exist on this shared server is scoped down
    # to just their own assignment, or zeroed out entirely for features
    # they can't reach at all (Databases/Backups/Mail/Cron/Firewall).
    if site_restricted:
        sites_count = len(scope_ids)
        databases_count = 0
        cron_count = 0
        firewall_count = 0
        if scope_ids:
            placeholders = ",".join("?" * len(scope_ids))
            php_sites = g.db.execute(
                f"SELECT COUNT(*) AS c FROM sites WHERE id IN ({placeholders}) AND site_type = 'php'", list(scope_ids)
            ).fetchone()["c"]
            node_sites = g.db.execute(
                f"SELECT COUNT(*) AS c FROM sites WHERE id IN ({placeholders}) AND site_type = 'node'", list(scope_ids)
            ).fetchone()["c"]
        else:
            php_sites = node_sites = 0
        backups_enabled = 0
        mail_accounts = 0
    else:
        sites_count = g.db.execute("SELECT COUNT(*) AS c FROM sites").fetchone()["c"]
        databases_count = g.db.execute("SELECT COUNT(*) AS c FROM databases").fetchone()["c"]
        try:
            cron_count = len(system_ops.list_cron_jobs())
        except system_ops.SystemOpError:
            cron_count = 0
        try:
            firewall_count = len(system_ops.list_firewall_rules())
        except system_ops.SystemOpError:
            firewall_count = 0
        php_sites = g.db.execute("SELECT COUNT(*) AS c FROM sites WHERE site_type = 'php'").fetchone()["c"]
        node_sites = g.db.execute("SELECT COUNT(*) AS c FROM sites WHERE site_type = 'node'").fetchone()["c"]
        backups_enabled = (
            g.db.execute("SELECT COUNT(*) AS c FROM sites WHERE auto_backup_enabled = 1").fetchone()["c"]
            + g.db.execute("SELECT COUNT(*) AS c FROM databases WHERE auto_backup_enabled = 1").fetchone()["c"]
        )
        mail_accounts = len(system_ops.list_mailboxes()) if system_ops.mail_server_available() else 0

    try:
        stats = system_ops.get_system_stats()
    except OSError:
        stats = None
    disk_view.apply(stats, g.db)

    try:
        server_info = system_ops.get_server_info()
    except OSError:
        server_info = {"os_name": "Unknown", "kernel": "Unknown", "cpu_model": "Unknown", "hostname": "unknown"}
    uptime = system_ops.get_uptime()

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        base_url=f"/{cfg.security_path}",
        site_restricted=site_restricted,
        sites_count=sites_count,
        databases_count=databases_count,
        cron_count=cron_count,
        firewall_count=firewall_count,
        stats=stats,
        terminal_enabled=is_terminal_enabled(g.db) if not site_restricted else False,
        php_sites=php_sites,
        node_sites=node_sites,
        backups_enabled=backups_enabled,
        mail_accounts=mail_accounts,
        server_info=server_info,
        uptime=uptime,
    )


@bp.route("/network.json")
@login_required
def network_json():
    try:
        totals = system_ops.get_network_totals()
    except OSError:
        totals = {"rx_bytes": 0, "tx_bytes": 0}
    return jsonify(totals)
