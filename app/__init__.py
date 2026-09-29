"""Flask app factory.

Everything meaningful is mounted under the random security-entrance path
(e.g. /a1b2c3d4/...) generated at install time. Anything outside that
prefix — including bare "/" — returns a generic 404, deliberately giving no
hint that a panel is running here at all (the same reason aaPanel uses a
random path instead of the guessable /admin or /login).
"""
from pathlib import Path

from flask import Flask, flash, g, redirect, request, session
from flask_sock import Sock
from flask_wtf import CSRFProtect

from .account import BLUEPRINT_TO_FEATURE
from .config import load_config
from .db import get_connection, init_db



def create_app(config_path: Path | None = None) -> Flask:
    app = Flask(__name__)

    cfg = load_config(config_path)
    app.secret_key = cfg.secret_key
    app.config["PANEL_CONFIG"] = cfg

    # Checked once at startup, not per-request — a license doesn't change
    # mid-process, and this avoids a filesystem read + signature verify on
    # every single page load. Restart the panel after replacing license.key.
    app.config["LICENSE_STATUS"] = {"valid": True, "reason": "", "customer": None, "expires_at": None}

    @app.context_processor
    def _inject_license_status():
        return {"license_status": app.config["LICENSE_STATUS"]}

    # Cookies must never be sent over plain HTTP or to another origin —
    # the panel always serves HTTPS (see run.py / systemd unit), so this
    # is safe to enforce unconditionally rather than making it configurable.
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    init_db(cfg.db_path)

    def get_db():
        if "db" not in g:
            g.db = get_connection(cfg.db_path)
        return g.db

    app.config["get_db"] = get_db

    @app.before_request
    def _open_db():
        g.db = get_db()

    @app.before_request
    def _enforce_viewer_read_only():
        # A "viewer" role can look at everything but change nothing —
        # enforced once, here, rather than re-implementing the check in
        # every single route across every blueprint. GET/HEAD/OPTIONS are
        # always allowed (that's the read side); anything else (every
        # mutation in this app is a POST — there's no PUT/DELETE) is
        # blocked unless the session belongs to an admin.
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        if request.endpoint == "auth.logout":  # always allowed, regardless of role
            return None
        if session.get("user_id") and session.get("role") == "viewer":
            flash("Viewers can look but can't make changes.", "error")
            return redirect(cfg.dashboard_url)
        return None

    @app.before_request
    def _enforce_custom_role_permissions():
        # A "custom" role only reaches the feature areas explicitly checked
        # for that account (see account.FEATURES/BLUEPRINT_TO_FEATURE) — for
        # those areas both read AND write work normally; every other
        # gate-able blueprint is entirely unreachable, not just read-only.
        # Dashboard/Account/Monitor/auth/static are never in
        # BLUEPRINT_TO_FEATURE, so they stay open to every logged-in user.
        if session.get("role") != "custom":
            return None
        if request.endpoint is None:
            return None
        blueprint = request.endpoint.split(".", 1)[0]
        feature = BLUEPRINT_TO_FEATURE.get(blueprint)
        if feature is None:
            return None
        allowed = set((session.get("permissions") or "").split(",")) if session.get("permissions") else set()
        if feature in allowed:
            return None
        flash("Your account doesn't have access to that feature.", "error")
        return redirect(cfg.dashboard_url)

    # Blueprints a site-restricted admin may still reach at all — their own
    # Website entry and its File Manager, plus the always-open
    # Dashboard/Monitor/About/auth. Everything else in BLUEPRINT_TO_FEATURE
    # (Databases, Backups, Firewall, Terminal, SSH, Docker, Mail Server,
    # Cron, App Store, Logs, Settings, Domains, ...) is completely
    # unreachable — not read-only, gone — matching "only their site + files,
    # nothing else".
    SITE_RESTRICTED_BLUEPRINTS = {"dashboard", "files", "sites", "monitor", "about", "auth"}
    SITE_RESTRICTED_FEATURES = {"sites", "files"}

    @app.before_request
    def _enforce_site_restricted_admin():
        # An 'admin' a Super Admin has locked to specific sites (site_scope)
        # can only reach the blueprints above — everything else redirects
        # home with an explanation. Which SITE(S) within those blueprints
        # (which domain's files, which row on the Website page) is enforced
        # separately, per-request, inside files.py/sites.py themselves —
        # this hook only decides which PAGES exist for this session at all.
        if session.get("role") != "admin" or not session.get("site_scope"):
            return None
        if request.endpoint is None:
            return None
        blueprint = request.endpoint.split(".", 1)[0]
        if blueprint in SITE_RESTRICTED_BLUEPRINTS:
            return None
        flash("Your account is restricted to your own website and its files only.", "error")
        return redirect(cfg.dashboard_url)

    def _has_feature(key: str) -> bool:
        role = session.get("role")
        if role == "admin" and session.get("site_scope"):
            return key in SITE_RESTRICTED_FEATURES
        if role != "custom":
            return True
        allowed = set((session.get("permissions") or "").split(",")) if session.get("permissions") else set()
        return key in allowed

    def _is_site_restricted() -> bool:
        return session.get("role") == "admin" and bool(session.get("site_scope"))

    @app.context_processor
    def _inject_has_feature():
        return {"has_feature": _has_feature, "site_restricted": _is_site_restricted()}

    @app.teardown_appcontext
    def _close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    CSRFProtect(app)

    from . import about, account, ai, app_store, auth, backup_jobs, backups, cron, dashboard, databases, disk_manager, docker_manager, domains, dropshipping, files, firewall, logs, mail_server, monitor, node_manager, oauth_google, php_security, settings, sites, ssh_access, tamper_proof, terminal, waf

    app.register_blueprint(auth.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(dashboard.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(sites.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(files.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(databases.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(firewall.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(cron.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(oauth_google.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(terminal.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(app_store.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(logs.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(backups.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(backup_jobs.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(ssh_access.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(settings.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(account.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(monitor.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(domains.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(docker_manager.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(mail_server.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(waf.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(ai.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(node_manager.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(tamper_proof.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(php_security.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(disk_manager.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(dropshipping.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(about.bp, url_prefix=f"/{cfg.security_path}")

    sock = Sock(app)
    terminal.register_terminal_ws(app, sock, cfg.security_path, get_db)

    return app
