"""Feature catalogue and the effective-access calculation for every account.

FEATURES/BLUEPRINT_TO_FEATURE are the single source of truth for what a
"feature" is — used by account.py/role_manager.py/team.py to render the
checkboxes and by app/__init__.py's before_request hooks to gate every
request by blueprint.

Admin accounts carry three Super-Admin-controlled limits:
  - permissions: "*" (every feature) or a comma list of feature keys.
  - site_scope: "" (whole server) or a comma list of site IDs. A
    domain-restricted admin can only ever hold SITE_SCOPED_FEATURES —
    everything else runs as root across the whole server, so pairing it
    with a domain restriction would make that restriction meaningless.
  - can_manage_users: may create further admins under itself (team.py),
    never with more features/sites than it holds itself.
An admin created by another admin (users.created_by) is additionally
clamped, on every request, to whatever its creator currently holds — so
narrowing a parent immediately narrows everyone below it too.
"""

ALL = "*"
# Stored in session["site_scope"] for a restricted account whose effective
# site set is empty. Any non-empty string means "restricted" to every check
# in the app, and it parses to zero site IDs — so it fails closed.
NO_SITES = "none"

# (feature key, label shown in the UI)
FEATURES = [
    ("sites", "Website / Sites + SSL"),
    ("domains", "Domains"),
    ("files", "File Manager"),
    ("databases", "Databases"),
    ("backups", "Backups"),
    ("backup_jobs", "Backup Jobs"),
    ("docker", "Docker"),
    ("firewall", "Security / Firewall"),
    ("waf", "WAF"),
    ("mail_server", "Mail Server"),
    ("logs", "Logs"),
    ("dropshipping", "Dropshipping"),
    ("ssh_access", "SSH Access"),
    ("terminal", "Terminal"),
    ("ai", "AI Assistant"),
    ("cron", "Cron Jobs"),
    ("app_store", "App Store"),
    ("settings", "Settings"),
]
FEATURE_KEYS = {key for key, _ in FEATURES}

# Maps every gate-able blueprint to the feature key that controls it — several
# blueprints can share one checkbox (e.g. node_manager/disk_manager are part
# of the "Website / Sites" area, not separate toggles of their own).
BLUEPRINT_TO_FEATURE = {
    "sites": "sites", "node_manager": "sites", "disk_manager": "sites",
    "domains": "domains",
    "files": "files",
    "databases": "databases",
    "backups": "backups",
    "backup_jobs": "backup_jobs",
    "docker_manager": "docker",
    "firewall": "firewall", "tamper_proof": "firewall", "php_security": "firewall",
    "waf": "waf",
    "mail_server": "mail_server",
    "logs": "logs",
    "dropshipping": "dropshipping",
    "ssh_access": "ssh_access",
    "terminal": "terminal",
    "ai": "ai",
    "cron": "cron",
    "app_store": "app_store",
    "settings": "settings", "oauth_google": "settings",
}

# Features that filter themselves down to the account's assigned sites, and
# so are the only ones a domain-restricted admin can be given. Mapped to the
# blueprints each one opens — deliberately NOT node_manager/disk_manager,
# which are server-wide even though they sit under "sites" above.
SITE_SCOPED_BLUEPRINTS = {
    "sites": {"sites"},
    "files": {"files"},
    "backups": {"backups"},
    "app_store": {"app_store"},
    "domains": {"domains"},
}
SITE_SCOPED_FEATURES = set(SITE_SCOPED_BLUEPRINTS)

# Reachable by every logged-in account regardless of features (their own
# content is scoped/redacted where needed).
ALWAYS_OPEN_BLUEPRINTS = {"dashboard", "monitor", "about", "auth", "static", "team"}

DISK_DISPLAY_MODES = ("real", "custom")

_MAX_CHAIN = 32


def parse_ids(value: str) -> set:
    return {int(x) for x in (value or "").split(",") if x.strip().isdigit()}


def _parse_features(value: str):
    """ALL, or a set of known feature keys."""
    if value == ALL:
        return ALL
    return {p for p in (value or "").split(",") if p in FEATURE_KEYS}


def _intersect_features(a, b):
    if a == ALL:
        return b if b == ALL else set(b)
    if b == ALL:
        return set(a)
    return a & b


def effective_access(db, user_id: int):
    """What this account can actually do right now, as the session-ready
    strings every check in the app reads — or None if the account no longer
    exists. Recomputed on every request (see app/__init__.py).
    """
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return None

    access = {
        "role": row["role"],
        "permissions": row["permissions"] or "",
        "site_scope": row["site_scope"] or "",
        "can_manage_users": 0,
        "disk_display": row["disk_display"] if row["disk_display"] in DISK_DISPLAY_MODES else "real",
        "disk_quota_gb": row["disk_quota_gb"] or 0,
    }
    if row["role"] == "super_admin":
        access.update(permissions=ALL, site_scope="", can_manage_users=1, disk_display="real")
        return access
    if row["role"] != "admin":
        return access

    features = _parse_features(row["permissions"])
    scope = parse_ids(row["site_scope"]) if row["site_scope"] else None
    can_manage = bool(row["can_manage_users"])
    disk_display, disk_quota = access["disk_display"], access["disk_quota_gb"]

    # Walk up the created_by chain: every ancestor admin caps this one.
    parent_id, seen = row["created_by"], {row["id"]}
    while parent_id:
        parent = db.execute("SELECT * FROM users WHERE id = ?", (parent_id,)).fetchone()
        if parent is None or parent["id"] in seen or len(seen) > _MAX_CHAIN or parent["role"] not in ("admin", "super_admin"):
            # Broken chain (deleted/demoted creator) — fail closed.
            features, scope, can_manage = set(), set(), False
            break
        if parent["role"] == "super_admin":
            break
        seen.add(parent["id"])
        features = _intersect_features(features, _parse_features(parent["permissions"]))
        if parent["site_scope"]:
            parent_scope = parse_ids(parent["site_scope"])
            scope = parent_scope if scope is None else scope & parent_scope
        can_manage = can_manage and bool(parent["can_manage_users"])
        if disk_display == "real" and parent["disk_display"] == "custom":
            disk_display, disk_quota = "custom", parent["disk_quota_gb"] or 0
        parent_id = parent["created_by"]

    if scope is not None:
        features = SITE_SCOPED_FEATURES.copy() if features == ALL else features & SITE_SCOPED_FEATURES

    access.update(
        permissions=ALL if features == ALL else ",".join(sorted(features)),
        site_scope="" if scope is None else (",".join(str(i) for i in sorted(scope)) or NO_SITES),
        can_manage_users=1 if can_manage else 0,
        disk_display=disk_display,
        disk_quota_gb=disk_quota,
    )
    return access


def session_has_feature(session, key: str) -> bool:
    """Whether the current session may use `key`, from the effective values
    the per-request refresh put into the session."""
    role = session.get("role")
    if role in ("super_admin", "viewer"):
        return True
    if role not in ("admin", "custom"):
        return False
    permissions = session.get("permissions") or ""
    return permissions == ALL or key in permissions.split(",")


def session_features(session):
    """ALL or the set of feature keys the current session holds."""
    if session.get("role") in ("super_admin", "viewer"):
        return ALL
    return _parse_features(session.get("permissions") or "")
