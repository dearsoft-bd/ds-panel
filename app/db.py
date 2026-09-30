"""SQLite storage for the panel's own metadata (users, login attempts, sites).

Deliberately SQLite, not MySQL/Postgres: the panel must be able to start up
and let an admin log in even before any database service is configured, and
a server control panel should not depend on the very kind of service (a DB
server) it exists to manage.
"""
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'admin',
    permissions TEXT NOT NULL DEFAULT '',
    site_scope TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_password_resets_user
    ON password_resets (user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    succeeded INTEGER NOT NULL,
    attempted_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts (ip_address, attempted_at);

CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    document_root TEXT NOT NULL,
    ssl_enabled INTEGER NOT NULL DEFAULT 0,
    php_version TEXT NOT NULL DEFAULT '8.1',
    site_type TEXT NOT NULL DEFAULT 'php',
    node_port INTEGER,
    auto_backup_enabled INTEGER NOT NULL DEFAULT 0,
    backup_retention INTEGER NOT NULL DEFAULT 7,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS databases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    db_name TEXT UNIQUE NOT NULL,
    db_user TEXT NOT NULL,
    auto_backup_enabled INTEGER NOT NULL DEFAULT 0,
    backup_retention INTEGER NOT NULL DEFAULT 7,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS db_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS backup_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_name TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS domain_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    domain TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS file_trash (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trash_name TEXT UNIQUE NOT NULL,
    original_rel_path TEXT NOT NULL,
    is_dir INTEGER NOT NULL,
    deleted_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS backup_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    job_type TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    schedule_type TEXT NOT NULL DEFAULT 'daily',
    schedule_time TEXT NOT NULL DEFAULT '02:30',
    schedule_weekday INTEGER NOT NULL DEFAULT 1,
    schedule_day INTEGER NOT NULL DEFAULT 1,
    custom_cron TEXT NOT NULL DEFAULT '',
    retention INTEGER NOT NULL DEFAULT 7,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT NOT NULL DEFAULT '',
    last_status TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sourcing_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT UNIQUE NOT NULL,
    api_base_url TEXT NOT NULL DEFAULT '',
    app_key TEXT NOT NULL DEFAULT '',
    app_secret TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dropship_sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    db_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sourced_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    source_product_id TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    opencart_product_id INTEGER,
    title TEXT NOT NULL,
    price REAL NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS fulfillment_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    opencart_order_id INTEGER NOT NULL,
    sourced_product_id INTEGER NOT NULL REFERENCES sourced_products(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    source_order_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    tracking_number TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ai_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL DEFAULT 'New chat',
    display_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL DEFAULT '[]',
    pending_action_json TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def get_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        _migrate(conn)
    finally:
        conn.close()


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    """Adds a column, tolerating two races at once:
    1. The column may already exist (checked via PRAGMA table_info first).
    2. Gunicorn starts multiple worker processes at once, each independently
       calling init_db() -> _migrate() against the SAME sqlite file on
       startup — two workers can both see the column missing and both
       attempt the ALTER, and SQLite has no "ADD COLUMN IF NOT EXISTS".
       The "duplicate column name" OperationalError from the loser of that
       race is caught and ignored here rather than crashing that worker's
       boot, since the outcome (column exists) is exactly what was wanted.
    """
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column in columns:
        return
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        conn.commit()
    except sqlite3.OperationalError as e:
        if "duplicate column name" not in str(e):
            raise


def _migrate(conn: sqlite3.Connection) -> None:
    """Small forward-only migrations for columns added after a table
    already existed on someone's install — CREATE TABLE IF NOT EXISTS
    above only helps on a fresh DB, not an upgrade.
    """
    _add_column_if_missing(conn, "sites", "php_version", "TEXT NOT NULL DEFAULT '8.1'")
    _add_column_if_missing(conn, "sites", "site_type", "TEXT NOT NULL DEFAULT 'php'")
    _add_column_if_missing(conn, "sites", "node_port", "INTEGER")
    _add_column_if_missing(conn, "sites", "auto_backup_enabled", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "sites", "backup_retention", "INTEGER NOT NULL DEFAULT 7")

    _add_column_if_missing(conn, "databases", "auto_backup_enabled", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "databases", "backup_retention", "INTEGER NOT NULL DEFAULT 7")

    _add_column_if_missing(conn, "users", "full_name", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "users", "email", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "users", "role", "TEXT NOT NULL DEFAULT 'admin'")
    _add_column_if_missing(conn, "users", "permissions", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "users", "site_scope", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "users", "created_by", "INTEGER")
    _add_column_if_missing(conn, "users", "can_manage_users", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "users", "disk_display", "TEXT NOT NULL DEFAULT 'real'")
    _add_column_if_missing(conn, "users", "disk_quota_gb", "INTEGER NOT NULL DEFAULT 0")

    # Admin accounts used to have no feature list at all: '' meant "every
    # feature", or "Website + File Manager only" when site-restricted. Admin
    # features are now explicit ('*' = all, see permissions.py), so translate
    # the old meaning once — guarded by a settings flag, because '' is also
    # a legitimate "no features" value afterwards.
    migrated = conn.execute("SELECT value FROM settings WHERE key = 'admin_features_migrated'").fetchone()
    if not migrated:
        conn.execute("UPDATE users SET permissions = '*' WHERE role = 'admin' AND permissions = '' AND site_scope = ''")
        conn.execute("UPDATE users SET permissions = 'files,sites' WHERE role = 'admin' AND permissions = '' AND site_scope != ''")
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_features_migrated', '1')")
        conn.commit()

    # Pre-existing installs: the single super-user tier used to just be
    # 'admin'. Promote the earliest-created 'admin' account to 'super_admin'
    # once, on upgrade — otherwise nobody on an existing install could ever
    # reach the new Super-Admin-only Account page to create the first one.
    # Guarded so it only ever fires if no super_admin exists yet at all.
    existing_super_admin = conn.execute(
        "SELECT COUNT(*) AS n FROM users WHERE role = 'super_admin'"
    ).fetchone()["n"]
    if not existing_super_admin:
        first_admin = conn.execute(
            "SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1"
        ).fetchone()
        if first_admin:
            conn.execute("UPDATE users SET role = 'super_admin' WHERE id = ?", (first_admin["id"],))
            conn.commit()

    _add_column_if_missing(conn, "sites", "cdn_provider", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "sites", "cdn_zone_id", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "sites", "cdn_api_token", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "sites", "cdn_secret_key", "TEXT NOT NULL DEFAULT ''")

    # Python site hosting (systemd + git-based deploy) — node_port is reused
    # as the Python app's local port too (a site is only ever one type, so
    # one shared "internal port" column is enough; system_ops keeps the two
    # types' port ranges non-overlapping anyway as a belt-and-suspenders).
    _add_column_if_missing(conn, "sites", "python_version", "TEXT NOT NULL DEFAULT '3.11'")
    _add_column_if_missing(conn, "sites", "git_repo", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "sites", "start_command", "TEXT NOT NULL DEFAULT ''")
