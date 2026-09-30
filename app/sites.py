"""Website/Domain + SSL — Phase 2. Create/list/delete nginx-served sites,
issue Let's Encrypt certificates. All privileged work goes through
system_ops.py; this module only validates input and updates the panel's
own site registry (SQLite).
"""
import re
from pathlib import Path

from flask import Blueprint, after_this_request, current_app, flash, g, redirect, render_template, request, send_file, session

from . import system_ops
from .security import login_required, restricted_site_ids

bp = Blueprint("sites", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SITE_TYPES = ["php", "node", "python"]


@bp.before_request
def _enforce_sites_scope():
    # A site-restricted admin can only see/act on the specific site row(s)
    # a Super Admin assigned — never the full site list, and never create
    # a new one (that's server-wide capacity, not "their" site).
    ids = restricted_site_ids()
    if ids is None:
        return None
    cfg = current_app.config["PANEL_CONFIG"]
    if request.endpoint == "sites.add_site":
        flash("Your account can't create new sites.", "error")
        return redirect(f"{cfg.dashboard_url}sites")
    site_id = (request.view_args or {}).get("site_id")
    if site_id is not None and site_id not in ids:
        flash("You can only manage your own site.", "error")
        return redirect(f"{cfg.dashboard_url}sites")
    return None


@bp.route("/sites")
@login_required
def list_sites():
    cfg = current_app.config["PANEL_CONFIG"]
    ids = restricted_site_ids()
    if ids is not None:
        # Fail CLOSED: a site-restricted admin whose site_scope parses to
        # zero valid site IDs (stale/deleted site, corrupted data, whatever
        # the cause) must see NO sites, never every site on the server. The
        # old code here fell through to "SELECT * FROM sites" in that case,
        # which silently handed a site-restricted account full visibility —
        # exactly backwards for a security boundary.
        rows = []
        if ids:
            placeholders = ",".join("?" * len(ids))
            rows = g.db.execute(
                f"SELECT * FROM sites WHERE id IN ({placeholders}) ORDER BY created_at DESC", list(ids)
            ).fetchall()
    else:
        rows = g.db.execute("SELECT * FROM sites ORDER BY created_at DESC").fetchall()
    base = f"/{cfg.security_path}"
    return render_template(
        "sites.html",
        sites=rows,
        site_restricted=(ids is not None),
        php_versions=system_ops.ALLOWED_PHP_VERSIONS,
        default_php_version=system_ops.DEFAULT_PHP_VERSION,
        python_versions=system_ops.installed_python_versions(),
        default_python_version=system_ops.DEFAULT_PYTHON_VERSION,
        site_types=SITE_TYPES,
        sites_root=str(system_ops.SITES_ROOT),
        base_url=base,
        dashboard_url=f"{base}/",
        logout_url=f"{base}/logout",
        username=session.get("username"),
    )


@bp.route("/sites/add", methods=["POST"])
@login_required
def add_site():
    cfg = current_app.config["PANEL_CONFIG"]
    domain = request.form.get("domain", "").strip().lower()
    want_ssl = request.form.get("ssl") == "on"
    admin_email = request.form.get("admin_email", "").strip()
    php_version = request.form.get("php_version", system_ops.DEFAULT_PHP_VERSION).strip()
    site_type = request.form.get("site_type", "php").strip()
    python_version = request.form.get("python_version", system_ops.DEFAULT_PYTHON_VERSION).strip()
    git_repo = request.form.get("git_repo", "").strip()
    start_command = request.form.get("start_command", "").strip()

    if not system_ops.is_valid_domain(domain):
        flash(f"'{domain}' doesn't look like a valid domain.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    if site_type not in SITE_TYPES:
        flash("Invalid site type selected.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    if site_type == "php" and php_version not in system_ops.ALLOWED_PHP_VERSIONS:
        flash("Invalid PHP version selected.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    if site_type == "python":
        if python_version not in system_ops.ALLOWED_PYTHON_VERSIONS:
            flash("Invalid Python version selected.", "error")
            return redirect(f"{cfg.dashboard_url}sites")
        if not system_ops.is_valid_git_repo_url(git_repo):
            flash("A valid git repository URL (https:// or git@...) is required for a Python site.", "error")
            return redirect(f"{cfg.dashboard_url}sites")
        if start_command and not system_ops.is_valid_start_command(start_command):
            flash("Start command may only contain letters, digits, spaces and - _ . : / $ = , @ % +", "error")
            return redirect(f"{cfg.dashboard_url}sites")

    existing = g.db.execute("SELECT id FROM sites WHERE domain = ?", (domain,)).fetchone()
    if existing:
        flash(f"{domain} already exists.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    if want_ssl and not EMAIL_RE.match(admin_email):
        flash("A valid admin email is required to issue an SSL certificate.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    node_port = None
    try:
        if site_type == "node":
            document_root = system_ops.create_site_directory(domain)
            existing_ports = [
                row["node_port"]
                for row in g.db.execute("SELECT node_port FROM sites WHERE node_port IS NOT NULL").fetchall()
            ]
            node_port = system_ops.allocate_node_port(existing_ports)
            system_ops.scaffold_node_app(domain, document_root, node_port)
            system_ops.write_node_nginx_vhost(domain, node_port)
            system_ops.start_node_app(domain, document_root, node_port)
        elif site_type == "python":
            # No create_site_directory() here — it drops a placeholder
            # index.html, and `git clone` refuses to clone into a
            # non-empty directory. The repo's own contents become the site.
            document_root = system_ops.clone_python_repo(domain, git_repo)
            try:
                existing_ports = [
                    row["node_port"]
                    for row in g.db.execute("SELECT node_port FROM sites WHERE node_port IS NOT NULL").fetchall()
                ]
                node_port = system_ops.allocate_python_port(existing_ports)
                venv_path = system_ops.create_python_venv(document_root, python_version)
                system_ops.write_python_nginx_vhost(domain, node_port)
                system_ops.write_python_systemd_unit(domain, document_root, venv_path, node_port, start_command)
                system_ops.start_python_app(domain)
            except system_ops.SystemOpError:
                # Roll back so the same domain can simply be retried — a
                # leftover clone would make the next attempt refuse to
                # clone, and a leftover vhost/unit would point at nothing.
                system_ops.stop_python_app(domain)
                try:
                    system_ops.remove_nginx_vhost(domain)
                except system_ops.SystemOpError:
                    pass
                system_ops.remove_python_checkout(domain)
                raise
        else:
            document_root = system_ops.create_site_directory(domain)
            system_ops.write_nginx_vhost(domain, php_version)
    except system_ops.SystemOpError as e:
        flash(f"Failed to create site: {e}", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    ssl_enabled = False
    if want_ssl:
        try:
            system_ops.issue_certificate(domain, admin_email)
            ssl_enabled = True
        except system_ops.SystemOpError as e:
            flash(
                f"Site created, but SSL issuance failed: {e}. "
                "Make sure the domain's DNS already points at this server, then retry.",
                "error",
            )

    g.db.execute(
        "INSERT INTO sites (domain, document_root, ssl_enabled, php_version, site_type, node_port, "
        "python_version, git_repo, start_command) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            domain, str(document_root), 1 if ssl_enabled else 0, php_version, site_type, node_port,
            python_version if site_type == "python" else system_ops.DEFAULT_PYTHON_VERSION,
            git_repo if site_type == "python" else "",
            start_command if site_type == "python" else "",
        ),
    )
    g.db.commit()

    flash(f"{domain} created" + (" with SSL." if ssl_enabled else "."), "success")
    return redirect(f"{cfg.dashboard_url}sites")


@bp.route("/sites/<int:site_id>/backup")
@login_required
def backup_site(site_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    try:
        backup_path = system_ops.backup_site(row["domain"])
    except system_ops.SystemOpError as e:
        flash(f"Backup failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    @after_this_request
    def _cleanup(response):
        backup_path.unlink(missing_ok=True)
        return response

    return send_file(backup_path, as_attachment=True, download_name=backup_path.name)


@bp.route("/sites/<int:site_id>/enable-ssl", methods=["POST"])
@login_required
def enable_ssl(site_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    admin_email = request.form.get("admin_email", "").strip()
    if not EMAIL_RE.match(admin_email):
        flash("A valid admin email is required to issue an SSL certificate.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    aliases = [
        r["domain"] for r in g.db.execute("SELECT domain FROM domain_aliases WHERE site_id = ?", (site_id,)).fetchall()
    ]

    try:
        system_ops.issue_certificate(row["domain"], admin_email, extra_domains=aliases)
    except system_ops.SystemOpError as e:
        flash(
            f"SSL issuance failed: {e}. "
            "Make sure the domain's DNS points at this server and port 80 is reachable, then retry.",
            "error",
        )
        return redirect(f"{cfg.dashboard_url}sites")

    g.db.execute("UPDATE sites SET ssl_enabled = 1 WHERE id = ?", (site_id,))
    g.db.commit()
    flash(f"SSL enabled for {row['domain']}.", "success")
    return redirect(f"{cfg.dashboard_url}sites")


@bp.route("/sites/<int:site_id>/auto-backup", methods=["POST"])
@login_required
def set_auto_backup(site_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    enabled = 1 if request.form.get("enabled") == "on" else 0
    retention = request.form.get("retention", 7, type=int) or 7
    retention = max(1, min(retention, 90))

    g.db.execute(
        "UPDATE sites SET auto_backup_enabled = ?, backup_retention = ? WHERE id = ?",
        (enabled, retention, site_id),
    )
    g.db.commit()
    flash(
        f"Auto Backup {'enabled' if enabled else 'disabled'} for {row['domain']}"
        + (f" (keeping last {retention})." if enabled else "."),
        "success",
    )
    return redirect(f"{cfg.dashboard_url}sites")


@bp.route("/sites/<int:site_id>/redeploy", methods=["POST"])
@login_required
def redeploy_site(site_id: int):
    """The entire "git-based deploy" story for a Python site: pull the
    latest commit into its existing checkout and restart its service.
    There is no File Manager upload step for this site type at all.
    """
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    if row["site_type"] != "python":
        flash("Redeploy is only available for Python (git-deployed) sites.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    try:
        system_ops.pull_python_repo(row["domain"])
        system_ops.create_python_venv(Path(row["document_root"]), row["python_version"])
        system_ops.restart_python_app(row["domain"])
    except system_ops.SystemOpError as e:
        flash(f"Redeploy failed: {e}", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    flash(f"{row['domain']} redeployed from git.", "success")
    return redirect(f"{cfg.dashboard_url}sites")


@bp.route("/sites/<int:site_id>/delete", methods=["POST"])
@login_required
def delete_site(site_id: int):
    cfg = current_app.config["PANEL_CONFIG"]
    row = g.db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not row:
        flash("Site not found.", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    try:
        system_ops.remove_nginx_vhost(row["domain"])
        if row["site_type"] == "node":
            system_ops.stop_node_app(row["domain"])
        elif row["site_type"] == "python":
            system_ops.stop_python_app(row["domain"])
    except system_ops.SystemOpError as e:
        flash(f"Failed to remove nginx config: {e}", "error")
        return redirect(f"{cfg.dashboard_url}sites")

    # Deliberately NOT deleting the document root — losing a merchant's
    # files because they clicked delete once is a much worse failure mode
    # than leaving an orphaned folder behind. File Manager (phase 3) is
    # where a deliberate file-level delete belongs.
    g.db.execute("DELETE FROM sites WHERE id = ?", (site_id,))
    g.db.commit()

    flash(f"{row['domain']} removed. Files were kept at {row['document_root']}.", "success")
    return redirect(f"{cfg.dashboard_url}sites")
