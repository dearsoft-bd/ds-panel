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

from .config import load_config
from .db import get_connection, init_db
from .permissions import (
    ALWAYS_OPEN_BLUEPRINTS,
    BLUEPRINT_TO_FEATURE,
    SITE_SCOPED_BLUEPRINTS,
    effective_access,
    session_features,
    session_has_feature,
)



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
    def _refresh_session_access():
        # role/permissions/site_scope are copied into the session at login,
        # but a Super Admin can change them for an account that's already
        # logged in elsewhere — without this, that other session keeps its
        # old (possibly unrestricted) access until it logs out. Recompute
        # the EFFECTIVE values (clamped by every creator up the chain — see
        # permissions.effective_access) on every request so changes apply
        # immediately, and drop the session if the account no longer exists.
        # Must stay registered before the _enforce_* hooks below.
        user_id = session.get("user_id")
        if not user_id:
            return None
        access = effective_access(g.db, user_id)
        if access is None:
            session.clear()
            return redirect(cfg.login_url)
        for key, value in access.items():
            if session.get(key) != value:  # only touch changed keys, so the cookie isn't re-issued every request
                session[key] = value
        return None

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
    def _enforce_feature_permissions():
        # "custom" and "admin" accounts only reach the feature areas their
        # effective permissions hold (admins: '*' = all, set by the Super
        # Admin in Role Manager) — for those areas both read AND write work
        # normally; every other gate-able blueprint is entirely unreachable,
        # not just read-only. Dashboard/Account/Monitor/auth/static are never
        # in BLUEPRINT_TO_FEATURE, so they stay open to every logged-in user.
        if session.get("role") not in ("custom", "admin"):
            return None
        if request.endpoint is None:
            return None
        blueprint = request.endpoint.split(".", 1)[0]
        feature = BLUEPRINT_TO_FEATURE.get(blueprint)
        if feature is None or session_has_feature(session, feature):
            return None
        flash("Your account doesn't have access to that feature.", "error")
        return redirect(cfg.dashboard_url)

    @app.before_request
    def _enforce_site_restricted_admin():
        # An 'admin' a Super Admin has locked to specific sites (site_scope)
        # can only reach the always-open blueprints plus the site-scoped ones
        # its features include — never Terminal/Cron/Docker/SSH/etc., which
        # run as root across the whole server (their feature bits are already
        # stripped by effective_access; this is the page-level backstop, and
        # it also blocks non-blueprint endpoints like the terminal WebSocket).
        # Which SITE(S) within those blueprints is enforced separately,
        # per-request, inside files.py/sites.py/backups.py/... themselves.
        if session.get("role") != "admin" or not session.get("site_scope"):
            return None
        if request.endpoint is None:
            return None
        blueprint = request.endpoint.split(".", 1)[0]
        if blueprint in ALWAYS_OPEN_BLUEPRINTS:
            return None
        features = session_features(session)
        if any(blueprint in bps for f, bps in SITE_SCOPED_BLUEPRINTS.items() if f in features):
            return None
        flash("Your account is restricted to your own website only.", "error")
        return redirect(cfg.dashboard_url)

    def _has_feature(key: str) -> bool:
        return session_has_feature(session, key)

    def _is_site_restricted() -> bool:
        return session.get("role") == "admin" and bool(session.get("site_scope"))

    @app.context_processor
    def _inject_has_feature():
        return {
            "has_feature": _has_feature,
            "site_restricted": _is_site_restricted(),
            "can_manage_team": session.get("role") == "admin" and bool(session.get("can_manage_users")),
        }

    @app.teardown_appcontext
    def _close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    CSRFProtect(app)

    from . import about, account, ai, app_store, auth, backup_jobs, backups, cron, dashboard, databases, disk_manager, docker_manager, domains, dropshipping, files, firewall, logs, mail_server, monitor, node_manager, oauth_google, php_security, role_manager, settings, sites, ssh_access, tamper_proof, team, terminal, waf

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
    app.register_blueprint(role_manager.bp, url_prefix=f"/{cfg.security_path}")
    app.register_blueprint(team.bp, url_prefix=f"/{cfg.security_path}")

    sock = Sock(app)
    terminal.register_terminal_ws(app, sock, cfg.security_path, get_db)

    return app
