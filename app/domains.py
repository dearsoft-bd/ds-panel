"""Domains — additional domain aliases pointing at an existing site
(e.g. both example.com and www.example.com serving the same PHP/Node
app), beyond the one primary domain each site already has. Nginx's own
server_name directive already supports multiple names natively, so this
is a thin layer over that: no per-alias document root or separate
config, every alias just gets added to the site's existing vhost.
"""
from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("domains", __name__)


@bp.route("/domains")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"

    sites = g.db.execute("SELECT * FROM sites ORDER BY domain").fetchall()
    aliases_by_site = {}
    for row in g.db.execute("SELECT * FROM domain_aliases ORDER BY domain").fetchall():
        aliases_by_site.setdefault(row["site_id"], []).append(row)

    return render_template(
        "domains.html",
        sites=sites,
        aliases_by_site=aliases_by_site,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


def _regenerate_vhost(site_row, extra_domains):
    if site_row["site_type"] == "node":
        system_ops.write_node_nginx_vhost(site_row["domain"], site_row["node_port"], extra_domains=extra_domains)
    elif site_row["site_type"] == "python":
        system_ops.write_python_nginx_vhost(site_row["domain"], site_row["node_port"], extra_domains=extra_domains)
    else:
        system_ops.write_nginx_vhost(site_row["domain"], site_row["php_version"], extra_domains=extra_domains)


@bp.route("/domains/add", methods=["POST"])
@login_required
def add_alias():
    cfg = current_app.config["PANEL_CONFIG"]
    site_id = request.form.get("site_id", type=int)
    alias_domain = request.form.get("domain", "").strip().lower()
    admin_email = request.form.get("admin_email", "").strip()

    site_row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not site_row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}domains")

    if not system_ops.is_valid_domain(alias_domain):
        flash(f"'{alias_domain}' doesn't look like a valid domain.", "error")
        return redirect(f"{cfg.dashboard_url}domains")

    # Must be unique across both primary domains AND every existing alias —
    # nginx can't route the same hostname to two different sites.
    taken = g.db.execute("SELECT id FROM sites WHERE domain = ?", (alias_domain,)).fetchone() or \
        g.db.execute("SELECT id FROM domain_aliases WHERE domain = ?", (alias_domain,)).fetchone()
    if taken:
        flash(f"'{alias_domain}' is already in use by another site or alias.", "error")
        return redirect(f"{cfg.dashboard_url}domains")

    existing_aliases = [
        r["domain"] for r in g.db.execute("SELECT domain FROM domain_aliases WHERE site_id = ?", (site_id,)).fetchall()
    ]
    new_alias_list = existing_aliases + [alias_domain]

    try:
        _regenerate_vhost(site_row, new_alias_list)
        if site_row["ssl_enabled"]:
            if not admin_email:
                raise system_ops.SystemOpError(
                    "This site has SSL enabled — an admin email is required to expand the certificate to cover the new domain."
                )
            system_ops.issue_certificate(site_row["domain"], admin_email, extra_domains=new_alias_list)
    except system_ops.SystemOpError as e:
        flash(f"Failed to add domain: {e}", "error")
        return redirect(f"{cfg.dashboard_url}domains")

    g.db.execute("INSERT INTO domain_aliases (site_id, domain) VALUES (?, ?)", (site_id, alias_domain))
    g.db.commit()
    flash(f"'{alias_domain}' now points to {site_row['domain']}.", "success")
    return redirect(f"{cfg.dashboard_url}domains")


@bp.route("/domains/<int:alias_id>/delete", methods=["POST"])
@login_required
def delete_alias(alias_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    alias_row = g.db.execute("SELECT * FROM domain_aliases WHERE id = ?", (alias_id,)).fetchone()
    if not alias_row:
        flash("Alias not found.", "error")
        return redirect(f"{cfg.dashboard_url}domains")

    site_row = g.db.execute("SELECT * FROM sites WHERE id = ?", (alias_row["site_id"],)).fetchone()
    if not site_row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}domains")

    remaining = [
        r["domain"] for r in g.db.execute(
            "SELECT domain FROM domain_aliases WHERE site_id = ? AND id != ?", (site_row["id"], alias_id)
        ).fetchall()
    ]

    try:
        _regenerate_vhost(site_row, remaining)
    except system_ops.SystemOpError as e:
        flash(f"Failed to remove domain: {e}", "error")
        return redirect(f"{cfg.dashboard_url}domains")

    g.db.execute("DELETE FROM domain_aliases WHERE id = ?", (alias_id,))
    g.db.commit()
    flash(
        f"'{alias_row['domain']}' no longer points to {site_row['domain']}."
        + (" Note: if SSL was enabled, the certificate still lists it until next renewal — this is harmless." if site_row["ssl_enabled"] else ""),
        "success",
    )
    return redirect(f"{cfg.dashboard_url}domains")
