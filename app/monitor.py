"""Monitor — live resource stats, per-service status, and a top-processes
snapshot. This is the deeper page the dashboard's small gauges link out
to; no historical/persisted graphing in v1 (that would need a periodic
sampler + its own storage — a reasonable v2 addition, not built yet).
"""
from flask import Blueprint, current_app, render_template, session

from . import system_ops
from .security import login_required, restricted_site_ids

bp = Blueprint("monitor", __name__)


@bp.route("/monitor")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    site_restricted = restricted_site_ids() is not None

    try:
        stats = system_ops.get_system_stats()
    except OSError:
        stats = None

    # CPU/RAM/disk totals, load, uptime and service status are all generic
    # server-wide numbers — none of them identify another tenant, so a
    # site-restricted admin still sees the full picture there. The top
    # processes list is different: process command lines routinely include
    # other sites' document-root paths (php-fpm pool names, node app
    # paths), which would leak exactly what this role is meant to hide —
    # so it's simply omitted for a restricted session, not filtered.
    processes = [] if site_restricted else system_ops.get_top_processes()

    return render_template(
        "monitor.html",
        stats=stats,
        site_restricted=site_restricted,
        services=system_ops.monitored_services(),
        uptime=system_ops.get_uptime(),
        load=system_ops.get_load_averages(),
        processes=processes,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )
