"""One-click app installer — WordPress, OpenCart, Joomla, ownCloud, Laravel.
Downloads the real upstream release, extracts it into an existing site's
document root, provisions a fresh database, and (for WordPress) writes
wp-config.php. The app's own web installer wizard is left for the user to
finish, same as every other one-click installer under the hood. Laravel is
the exception — no ready-made release zip exists, so it's installed via a
real `composer create-project` run instead (see system_ops.install_laravel).
"""
import re
import secrets
from pathlib import Path

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session

from . import system_ops
from .security import login_required

bp = Blueprint("app_store", __name__)

APPS = {
    "wordpress": "WordPress",
    "opencart": "OpenCart",
    "joomla": "Joomla",
    "owncloud": "ownCloud",
    "laravel": "Laravel",
}
# Apps that don't need a database provisioned (own storage/no DB step).
APPS_NO_DATABASE = {"laravel"}

# Server-wide software (not installed into a single site's document root the
# way WordPress/OpenCart are) — each entry maps to an is_installed check and
# an installer function in system_ops.
SERVER_SOFTWARE = {
    "apache": {
        "label": "Apache",
        "description": "A second web server alongside nginx, listening on port 8080.",
        "is_installed": system_ops.apache_installed,
        "install": system_ops.install_apache,
        "manage_url": None,
    },
    "waf": {
        "label": "WAF (ModSecurity)",
        "description": "ModSecurity + the OWASP Core Rule Set for nginx, server-wide. Off by default after install.",
        "is_installed": system_ops.waf_installed,
        "install": system_ops.install_waf,
        "manage_url": "waf",
    },
    "node_manager": {
        "label": "Node.js Version Manager",
        "description": "Install and switch between Node.js 18/20/22 system-wide, for sites that need a specific version.",
        "is_installed": system_ops.node_manager_installed,
        "install": system_ops.install_node_manager,
        "manage_url": "node-manager",
    },
}

# Tools that need no installation (built on things already on the server —
# php.ini, chattr, lsblk/mount) — just a card linking straight to their page.
TOOLS = {
    "php_security": {
        "label": "PHP Code Security",
        "description": "Disable dangerous PHP functions (exec, shell_exec, proc_open, ...) per PHP version.",
        "url": "php-security",
    },
    "tamper_proof": {
        "label": "Website Tamper-proof",
        "description": "Lock a site's files against modification using the filesystem's immutable attribute.",
        "url": "tamper-proof",
    },
    "disk_manager": {
        "label": "Disk Mount Manager",
        "description": "List disks/partitions and mount/unmount one on demand — never touches /etc/fstab.",
        "url": "disk-manager",
    },
}


def _random_password(length: int = 16) -> str:
    # No quotes/backslashes/ambiguous chars — this ends up inside a PHP
    # single-quoted string (wp-config.php) and a MySQL literal.
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _db_identifier_for(domain: str, prefix: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]", "_", domain).strip("_")
    return f"{prefix}_{slug}"[:64]


@bp.route("/app-store")
@login_required
def index():
    cfg = current_app.config["PANEL_CONFIG"]
    base = f"/{cfg.security_path}"
    sites = g.db.execute(
        "SELECT * FROM sites WHERE site_type = 'php' ORDER BY domain"
    ).fetchall()
    software_status = {
        key: entry["is_installed"]() for key, entry in SERVER_SOFTWARE.items()
    }
    return render_template(
        "app_store.html",
        apps=APPS,
        sites=sites,
        opencart_versions=list(system_ops.OPENCART_VERSIONS.keys()),
        default_opencart_version=system_ops.DEFAULT_OPENCART_VERSION,
        server_software=SERVER_SOFTWARE,
        software_status=software_status,
        tools=TOOLS,
        cdn_providers=CDN_PROVIDERS,
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/app-store/install", methods=["POST"])
@login_required
def install():
    cfg = current_app.config["PANEL_CONFIG"]
    site_id = request.form.get("site_id", type=int)
    app_key = request.form.get("app", "").strip()

    if app_key not in APPS:
        flash("Unknown app.", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    document_root = Path(row["document_root"])
    prefix = {"wordpress": "wp", "opencart": "oc", "joomla": "jm", "owncloud": "oc2"}.get(app_key, app_key)
    db_name = _db_identifier_for(row["domain"], prefix)
    db_user = db_name
    db_password = _random_password()

    try:
        if app_key not in APPS_NO_DATABASE:
            system_ops.create_database(db_name, db_user, db_password)

        if app_key == "wordpress":
            system_ops.install_wordpress(row["domain"], document_root, db_name, db_user, db_password)
            finish_url = f"http://{row['domain']}/wp-admin/install.php"
            creds_note = f"Database: {db_name} / user: {db_user} / password: {db_password} (already written into wp-config.php)."
        elif app_key == "opencart":
            oc_version = request.form.get("version", system_ops.DEFAULT_OPENCART_VERSION).strip()
            system_ops.install_opencart(row["domain"], document_root, oc_version)
            finish_url = f"http://{row['domain']}/install/"
            creds_note = f"OpenCart {oc_version}. Database: {db_name} / user: {db_user} / password: {db_password} (enter these in OpenCart's installer)."
        elif app_key == "joomla":
            system_ops.install_joomla(row["domain"], document_root)
            finish_url = f"http://{row['domain']}/installation/"
            creds_note = f"Database: {db_name} / user: {db_user} / password: {db_password} (enter these in Joomla's installer)."
        elif app_key == "owncloud":
            system_ops.install_owncloud(row["domain"], document_root)
            finish_url = f"http://{row['domain']}/"
            creds_note = f"Database: {db_name} / user: {db_user} / password: {db_password} (enter these in ownCloud's setup wizard)."
        else:  # laravel
            public_root = system_ops.install_laravel(row["domain"], document_root)
            system_ops.write_nginx_vhost(row["domain"], row["php_version"], document_root_override=public_root)
            finish_url = f"http://{row['domain']}/"
            creds_note = (
                "No database was provisioned — Laravel 11 defaults to SQLite out of the box; "
                "edit .env if you'd rather point it at MySQL."
            )
    except system_ops.SystemOpError as e:
        flash(f"Install failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    flash(
        f"{APPS[app_key]} installed into {row['domain']}. {creds_note} "
        f"Finish setup at {finish_url}",
        "success",
    )
    return redirect(f"{cfg.dashboard_url}app-store")


@bp.route("/app-store/install-software", methods=["POST"])
@login_required
def install_software():
    cfg = current_app.config["PANEL_CONFIG"]
    key = request.form.get("software", "").strip()

    entry = SERVER_SOFTWARE.get(key)
    if not entry:
        flash("Unknown software.", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    try:
        entry["install"]()
    except system_ops.SystemOpError as e:
        flash(f"Install failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    flash(f"{entry['label']} installed.", "success")
    return redirect(f"{cfg.dashboard_url}app-store")


# ---- CDN (Cloudflare + Tencent EdgeOne) — connect an existing zone, then
# purge cache from here. No DNS management in v1 (confirmed with the user).
CDN_PROVIDERS = {
    "cloudflare": "Cloudflare",
    "edgeone": "Tencent EdgeOne",
}


@bp.route("/app-store/cdn/save", methods=["POST"])
@login_required
def cdn_save():
    cfg = current_app.config["PANEL_CONFIG"]
    site_id = request.form.get("site_id", type=int)
    provider = request.form.get("provider", "").strip()
    zone_id = request.form.get("zone_id", "").strip()
    api_token = request.form.get("api_token", "").strip()
    secret_key = request.form.get("secret_key", "").strip()

    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    if provider and provider not in CDN_PROVIDERS:
        flash("Unknown CDN provider.", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    g.db.execute(
        "UPDATE sites SET cdn_provider = ?, cdn_zone_id = ?, cdn_api_token = ?, cdn_secret_key = ? WHERE id = ?",
        (provider, zone_id, api_token, secret_key, site_id),
    )
    g.db.commit()

    if not provider:
        flash(f"CDN disconnected from {row['domain']}.", "success")
        return redirect(f"{cfg.dashboard_url}app-store")

    try:
        if provider == "cloudflare":
            status = system_ops.cloudflare_zone_status(zone_id, api_token)
        else:
            status = system_ops.edgeone_zone_status(api_token, secret_key, zone_id)
    except system_ops.SystemOpError as e:
        flash(f"Saved, but couldn't verify the zone: {e}", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    flash(f"{CDN_PROVIDERS[provider]} connected to {row['domain']} (zone: {status.get('name')}, status: {status.get('status')}).", "success")
    return redirect(f"{cfg.dashboard_url}app-store")


@bp.route("/app-store/cdn/purge", methods=["POST"])
@login_required
def cdn_purge():
    cfg = current_app.config["PANEL_CONFIG"]
    site_id = request.form.get("site_id", type=int)

    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row or not row["cdn_provider"]:
        flash("This site isn't connected to a CDN yet.", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    try:
        if row["cdn_provider"] == "cloudflare":
            system_ops.cloudflare_purge_cache(row["cdn_zone_id"], row["cdn_api_token"])
        else:
            system_ops.edgeone_purge_cache(row["cdn_api_token"], row["cdn_secret_key"], row["cdn_zone_id"])
    except system_ops.SystemOpError as e:
        flash(f"Purge failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}app-store")

    flash(f"Cache purged for {row['domain']}.", "success")
    return redirect(f"{cfg.dashboard_url}app-store")
