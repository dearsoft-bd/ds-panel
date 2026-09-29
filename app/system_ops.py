"""Every privileged OS-level operation the panel performs lives here, and
ONLY here — nginx config writes, certbot calls, service reloads. This is
the single most security-critical module in the codebase.

Two rules, without exception:
  1. subprocess calls always use an argument LIST, never `shell=True` with
     an interpolated string. This is what actually prevents command
     injection — a validated-looking string is not enough on its own.
  2. Anything that becomes a filename or a domain in a shell-adjacent
     context (nginx config, certbot -d flag) is validated against a strict
     allow-list regex FIRST, as defense in depth on top of rule 1 — so even
     a future refactor that accidentally introduces string interpolation
     somewhere still can't be handed a path-traversal or injection payload.
"""
import hashlib
import hmac
import json
import re
import subprocess
import time
from pathlib import Path

import requests

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

SITES_ROOT = Path("/var/www/dearsoft-sites")
NGINX_AVAILABLE = Path("/etc/nginx/sites-available")
NGINX_ENABLED = Path("/etc/nginx/sites-enabled")

# 8.1 is the default for new sites; 7.2 (legacy), 8.2, and 8.5 are opt-in
# per site. All are installed by install.sh via ppa:ondrej/php since
# Ubuntu 24.04's own repos only ship one current version.
ALLOWED_PHP_VERSIONS = ["7.2", "8.1", "8.2", "8.5"]
DEFAULT_PHP_VERSION = "8.1"


class SystemOpError(RuntimeError):
    pass


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def safe_path(relative_path: str) -> Path:
    """Resolves a user-supplied relative path against SITES_ROOT and
    rejects anything that escapes it — the File Manager's single most
    important security check (classic path-traversal, e.g. "../../etc/passwd"
    or an absolute path smuggled through the same parameter). Every File
    Manager operation must call this before touching the filesystem.
    """
    relative_path = (relative_path or "").strip().lstrip("/")
    candidate = (SITES_ROOT / relative_path).resolve()
    try:
        candidate.relative_to(SITES_ROOT.resolve())
    except ValueError:
        raise SystemOpError(f"Path escapes the managed sites root: {relative_path!r}")
    return candidate


def own_www_data(path: Path) -> None:
    """Every File Manager write (upload, unzip, new file/folder, paste,
    rename) runs inside the panel's own process — which is root, for its
    other privileged duties — so anything it creates lands owned by root
    by default. PHP-FPM runs as www-data and can't reliably read/write
    root-owned files, so every such write must be handed back to
    www-data immediately afterward. Silently a no-op on a path that
    vanished before this ran (e.g. a rename's old location).
    """
    subprocess.run(["chown", "-R", "www-data:www-data", str(path)], capture_output=True)


def _run(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    if not isinstance(args, list):  # belt-and-suspenders against a future misuse
        raise TypeError("system_ops._run() requires an argument list, never a string")
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise SystemOpError(f"{' '.join(args)} failed: {e.stderr.strip()}") from e
    except subprocess.TimeoutExpired as e:
        raise SystemOpError(f"{' '.join(args)} timed out after {timeout}s") from e


def document_root_for(domain: str) -> Path:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")
    return SITES_ROOT / domain


# Shared placeholder shown on a freshly-created site before real content is
# uploaded — used verbatim by both the PHP static index.html and the Node.js
# starter server.js, so a new site looks the same regardless of which type
# it is. Self-contained (no external fonts/CDN) since the site itself
# shouldn't depend on anything beyond this server.
PLACEHOLDER_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{domain}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: radial-gradient(circle at 20% 20%, #2a2118 0%, #0c0b0a 55%);
    color: #f0ece4;
  }}
  .card {{
    max-width: 560px;
    margin: 24px;
    padding: 48px 40px;
    text-align: center;
    background: #171512;
    border: 1px solid #2e2a24;
    border-radius: 16px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.45);
  }}
  .badge {{
    display: inline-block;
    padding: 6px 16px;
    margin-bottom: 20px;
    border-radius: 999px;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: #0c0b0a;
    background: linear-gradient(135deg, #facc15, #f97316);
  }}
  h1 {{
    margin: 0 0 12px;
    font-size: 28px;
    background: linear-gradient(135deg, #facc15, #f97316);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }}
  p {{
    margin: 0 0 8px;
    color: #9c9284;
    line-height: 1.6;
  }}
  .domain {{
    color: #f0ece4;
    font-weight: 600;
  }}
  .thanks {{
    margin-top: 28px;
    padding-top: 24px;
    border-top: 1px solid #2e2a24;
    font-size: 14px;
  }}
  .footer {{
    margin-top: 8px;
    font-size: 12px;
    color: #5a5348;
  }}
  .footer a {{
    color: #f97316;
    text-decoration: none;
  }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">Under Construction</span>
    <h1>Something great is on the way</h1>
    <p><span class="domain">{domain}</span> is set up and ready — the real
    content just hasn't been uploaded yet.</p>
    <p class="thanks">Thank you for stopping by. Please check back soon!</p>
    <p class="footer">Powered by <a href="#">DS Panel</a></p>
  </div>
</body>
</html>
"""


def create_site_directory(domain: str) -> Path:
    """Creates the document root and drops a placeholder index page.
    Idempotent — safe to call even if the directory already exists.
    """
    root = document_root_for(domain)
    root.mkdir(parents=True, exist_ok=True)
    index = root / "index.html"
    if not index.exists():
        index.write_text(PLACEHOLDER_HTML.format(domain=domain), encoding="utf-8")
    own_www_data(root)
    return root


VHOST_TEMPLATE = """server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    root {document_root};
    index index.html index.htm index.php;

    # Large uploads/imports (theme demo data, product image bulk import,
    # etc.) — nginx's own default of 1m causes a 413 long before PHP's own
    # upload_max_filesize/post_max_size (bumped to match, see php_version
    # ini override) ever get a say.
    client_max_body_size 1024m;

    location / {{
        try_files $uri $uri/ /index.php?$args;
    }}

    location ~ \\.php$ {{
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php{php_version}-fpm.sock;
        fastcgi_read_timeout 300;
        # nginx's own $https var is "on" only when the matching listen block
        # is SSL — Certbot appends a listen 443 ssl block to this same file
        # later but never adds this param itself, so without it PHP never
        # learns the connection was HTTPS (mod_php/Apache set this
        # automatically; php-fpm needs it passed explicitly). Missing this
        # causes apps to generate http:// URLs on an https:// page, which
        # browsers silently block as mixed content for embedded resources.
        fastcgi_param HTTPS $https;
    }}

    location ~ /\\.ht {{
        deny all;
    }}
}}
"""


NODE_VHOST_TEMPLATE = """server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    client_max_body_size 1024m;

    location / {{
        proxy_pass http://127.0.0.1:{node_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }}
}}
"""


def _server_names(domain: str, extra_domains: list[str] | None = None) -> str:
    names = [domain] + list(extra_domains or [])
    for name in names:
        if not is_valid_domain(name):
            raise SystemOpError(f"Invalid domain: {name!r}")
    return " ".join(names)


def write_nginx_vhost(domain: str, php_version: str = DEFAULT_PHP_VERSION, extra_domains: list[str] | None = None,
                       document_root_override: Path | None = None) -> Path:
    if php_version not in ALLOWED_PHP_VERSIONS:
        raise SystemOpError(f"Unsupported PHP version: {php_version!r}")
    server_name = _server_names(domain, extra_domains)

    # Laravel-style apps serve from a "public/" subdirectory, not the site
    # root — this override lets the App Store installer point nginx there
    # after installing, without every other caller needing to know about it.
    document_root = document_root_override or document_root_for(domain)
    config_path = NGINX_AVAILABLE / f"{domain}.conf"
    config_path.write_text(
        VHOST_TEMPLATE.format(domain=server_name, document_root=document_root, php_version=php_version),
        encoding="utf-8",
    )

    enabled_link = NGINX_ENABLED / f"{domain}.conf"
    if not enabled_link.exists():
        enabled_link.symlink_to(config_path)

    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])
    return config_path


def write_node_nginx_vhost(domain: str, node_port: int, extra_domains: list[str] | None = None) -> Path:
    server_name = _server_names(domain, extra_domains)

    config_path = NGINX_AVAILABLE / f"{domain}.conf"
    config_path.write_text(
        NODE_VHOST_TEMPLATE.format(domain=server_name, node_port=node_port),
        encoding="utf-8",
    )

    enabled_link = NGINX_ENABLED / f"{domain}.conf"
    if not enabled_link.exists():
        enabled_link.symlink_to(config_path)

    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])
    return config_path


def remove_nginx_vhost(domain: str) -> None:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")

    enabled_link = NGINX_ENABLED / f"{domain}.conf"
    config_path = NGINX_AVAILABLE / f"{domain}.conf"

    if enabled_link.exists() or enabled_link.is_symlink():
        enabled_link.unlink()
    if config_path.exists():
        config_path.unlink()

    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])


# ---- System resource stats (dashboard widgets) ----------------------------
# Read directly from /proc and statvfs — no psutil dependency needed for
# these three simple numbers.
def get_system_stats() -> dict:
    import os as _os

    # Load average + CPU count -> a rough "load as % of capacity" gauge,
    # same idea as aaPanel's "Normal" ring.
    with open("/proc/loadavg") as f:
        load_fields = f.read().split()
    load1, load5, load15 = float(load_fields[0]), float(load_fields[1]), float(load_fields[2])
    cpu_count = _os.cpu_count() or 1
    load_percent = min(100, round((load1 / cpu_count) * 100))

    # RAM — split into used/buffers/cache/free so the dashboard can show a
    # legend breakdown, not just a single used-vs-total percentage.
    mem_total_kb = mem_available_kb = mem_free_kb = mem_buffers_kb = mem_cached_kb = 0
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                mem_total_kb = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                mem_available_kb = int(line.split()[1])
            elif line.startswith("MemFree:"):
                mem_free_kb = int(line.split()[1])
            elif line.startswith("Buffers:"):
                mem_buffers_kb = int(line.split()[1])
            elif line.startswith("Cached:"):
                mem_cached_kb = int(line.split()[1])
    mem_used_kb = mem_total_kb - mem_available_kb
    mem_percent = round((mem_used_kb / mem_total_kb) * 100) if mem_total_kb else 0

    # Disk (root filesystem)
    st = _os.statvfs("/")
    disk_total = st.f_frsize * st.f_blocks
    disk_free = st.f_frsize * st.f_bavail
    disk_used = disk_total - disk_free
    disk_percent = round((disk_used / disk_total) * 100) if disk_total else 0

    def _gb(kb_or_bytes, is_kb=False):
        bytes_val = kb_or_bytes * 1024 if is_kb else kb_or_bytes
        return round(bytes_val / (1024 ** 3), 1)

    return {
        "load_percent": load_percent,
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "cpu_count": cpu_count,
        "mem_percent": mem_percent,
        "mem_used_gb": _gb(mem_used_kb, is_kb=True),
        "mem_buffers_gb": _gb(mem_buffers_kb, is_kb=True),
        "mem_cached_gb": _gb(mem_cached_kb, is_kb=True),
        "mem_free_gb": _gb(mem_free_kb, is_kb=True),
        "mem_total_gb": _gb(mem_total_kb, is_kb=True),
        "disk_percent": disk_percent,
        "disk_used_gb": _gb(disk_used),
        "disk_free_gb": _gb(disk_free),
        "disk_total_gb": _gb(disk_total),
    }


def get_server_info() -> dict:
    """Static-ish server identity info for the dashboard's System
    Information card — OS name, kernel, CPU model, all read straight from
    the usual /proc and /etc sources rather than shelling out where a
    plain file read will do.
    """
    import platform
    import socket

    os_name = "Unknown"
    if Path("/etc/os-release").is_file():
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip().strip('"')
                break

    cpu_model = "Unknown"
    if Path("/proc/cpuinfo").is_file():
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break

    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"

    return {
        "os_name": os_name,
        "kernel": platform.release(),
        "cpu_model": cpu_model,
        "hostname": hostname,
    }


def get_network_totals() -> dict:
    """Cumulative bytes sent/received since boot, summed across every
    real interface (loopback excluded) — a single point-in-time snapshot.
    The dashboard's live traffic graph calls this every couple of seconds
    from JS and computes the rate itself from consecutive snapshots,
    rather than this function trying to measure a rate server-side.
    """
    rx_total = tx_total = 0
    with open("/proc/net/dev") as f:
        lines = f.readlines()[2:]  # first two lines are headers
    for line in lines:
        iface, rest = line.split(":", 1)
        iface = iface.strip()
        if iface == "lo":
            continue
        fields = rest.split()
        rx_total += int(fields[0])
        tx_total += int(fields[8])
    return {"rx_bytes": rx_total, "tx_bytes": tx_total}


# ---- Database management (MySQL/MariaDB) ---------------------------------
# Identifiers (db/user names) can't be parameterized in SQL the way values
# can, so a strict allow-list regex is the actual safety mechanism here —
# not just defense in depth like elsewhere in this file. Anything not
# matching this never reaches a query.
DB_IDENTIFIER_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")


def is_valid_db_identifier(name: str) -> bool:
    return bool(DB_IDENTIFIER_RE.match(name))


def _mysql_exec(sql: str) -> str:
    result = _run(["mysql", "-u", "root", "-e", sql])
    return result.stdout


def list_databases() -> list[str]:
    out = _mysql_exec("SHOW DATABASES;")
    system_dbs = {"information_schema", "mysql", "performance_schema", "sys"}
    return [line for line in out.splitlines()[1:] if line not in system_dbs]


def create_database(db_name: str, db_user: str, db_password: str) -> None:
    if not is_valid_db_identifier(db_name):
        raise SystemOpError(f"Invalid database name: {db_name!r}")
    if not is_valid_db_identifier(db_user):
        raise SystemOpError(f"Invalid database username: {db_user!r}")
    if not db_password or len(db_password) < 8:
        raise SystemOpError("Database password must be at least 8 characters.")

    # db_password is passed as a bound value inside the -e string, not an
    # identifier — MySQL string literals are safe here because it's never
    # concatenated from raw user text into a shell command (subprocess.run
    # gets it as one argument, and the value is single-quoted for SQL with
    # its own quotes doubled, the standard SQL-literal escape).
    escaped_password = db_password.replace("'", "''")
    _mysql_exec(f"CREATE DATABASE IF NOT EXISTS `{db_name}`;")
    _mysql_exec(
        f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{escaped_password}';"
    )
    _mysql_exec(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost';")
    _mysql_exec("FLUSH PRIVILEGES;")


def set_user_password(db_user: str, new_password: str) -> None:
    if not is_valid_db_identifier(db_user):
        raise SystemOpError(f"Invalid database username: {db_user!r}")
    if not new_password or len(new_password) < 8:
        raise SystemOpError("Password must be at least 8 characters.")

    escaped_password = new_password.replace("'", "''")
    _mysql_exec(f"ALTER USER '{db_user}'@'localhost' IDENTIFIED BY '{escaped_password}';")
    _mysql_exec("FLUSH PRIVILEGES;")


def reassign_database_user(db_name: str, old_user: str, new_user: str) -> None:
    """Grants new_user access to db_name and revokes old_user's — used when
    editing a database to switch which existing user owns it. old_user
    itself is left alone (not dropped): it may still be granted on other
    databases, same reasoning as drop_database()'s drop_user flag.
    """
    if not is_valid_db_identifier(db_name):
        raise SystemOpError(f"Invalid database name: {db_name!r}")
    if not is_valid_db_identifier(old_user):
        raise SystemOpError(f"Invalid database username: {old_user!r}")
    if not is_valid_db_identifier(new_user):
        raise SystemOpError(f"Invalid database username: {new_user!r}")

    _mysql_exec(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{new_user}'@'localhost';")
    if new_user != old_user:
        _mysql_exec(f"REVOKE ALL PRIVILEGES ON `{db_name}`.* FROM '{old_user}'@'localhost';")
    _mysql_exec("FLUSH PRIVILEGES;")


def create_mysql_user_only(db_user: str, db_password: str) -> None:
    """Creates a MySQL user with no database/grant attached yet — for
    provisioning a user ahead of time, to be attached to one or more
    databases later via grant_database_to_existing_user().
    """
    if not is_valid_db_identifier(db_user):
        raise SystemOpError(f"Invalid database username: {db_user!r}")
    if not db_password or len(db_password) < 8:
        raise SystemOpError("Password must be at least 8 characters.")

    escaped_password = db_password.replace("'", "''")
    _mysql_exec(f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{escaped_password}';")
    _mysql_exec("FLUSH PRIVILEGES;")


def drop_mysql_user_only(db_user: str) -> None:
    if not is_valid_db_identifier(db_user):
        raise SystemOpError(f"Invalid database username: {db_user!r}")
    _mysql_exec(f"DROP USER IF EXISTS '{db_user}'@'localhost';")
    _mysql_exec("FLUSH PRIVILEGES;")


def grant_database_to_existing_user(db_name: str, db_user: str) -> None:
    """Same as create_database(), minus creating the user or needing a
    password — for attaching an already-existing MySQL user (one created
    for a previous database) to an additional one.
    """
    if not is_valid_db_identifier(db_name):
        raise SystemOpError(f"Invalid database name: {db_name!r}")
    if not is_valid_db_identifier(db_user):
        raise SystemOpError(f"Invalid database username: {db_user!r}")

    _mysql_exec(f"CREATE DATABASE IF NOT EXISTS `{db_name}`;")
    _mysql_exec(f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost';")
    _mysql_exec("FLUSH PRIVILEGES;")


def drop_database(db_name: str, db_user: str, drop_user: bool = True) -> None:
    """`drop_user` must be False when the same MySQL user is still granted
    on other databases — dropping the user would revoke their access to
    those too, not just this one.
    """
    if not is_valid_db_identifier(db_name):
        raise SystemOpError(f"Invalid database name: {db_name!r}")
    if not is_valid_db_identifier(db_user):
        raise SystemOpError(f"Invalid database username: {db_user!r}")

    _mysql_exec(f"DROP DATABASE IF EXISTS `{db_name}`;")
    if drop_user:
        _mysql_exec(f"DROP USER IF EXISTS '{db_user}'@'localhost';")


# ---- Firewall (ufw wrapper) -----------------------------------------------
def list_firewall_rules() -> list[str]:
    out = _run(["ufw", "status", "numbered"]).stdout
    return [line for line in out.splitlines() if line.strip()]


def allow_port(port: int, protocol: str = "tcp") -> None:
    if not (1 <= port <= 65535):
        raise SystemOpError(f"Invalid port: {port}")
    if protocol not in ("tcp", "udp"):
        raise SystemOpError(f"Invalid protocol: {protocol}")
    _run(["ufw", "allow", f"{port}/{protocol}"])


def deny_port(port: int, protocol: str = "tcp") -> None:
    if not (1 <= port <= 65535):
        raise SystemOpError(f"Invalid port: {port}")
    if protocol not in ("tcp", "udp"):
        raise SystemOpError(f"Invalid protocol: {protocol}")
    _run(["ufw", "delete", "allow", f"{port}/{protocol}"])


# ---- Cron (root's own crontab only, for v1) --------------------------------
# Uses the real `crontab` binary via stdin, never a hand-rolled parser/writer
# for /var/spool/cron — same "reuse proven tools" rule as everywhere else.
def list_cron_jobs() -> list[str]:
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    except FileNotFoundError:
        raise SystemOpError("cron is not installed on this server.")
    if result.returncode != 0:
        return []  # no crontab yet for this user — not an error
    return [line for line in result.stdout.splitlines() if line.strip() and not line.strip().startswith("#")]


def add_cron_job(schedule: str, command: str) -> None:
    fields = schedule.strip().split()
    if len(fields) != 5:
        raise SystemOpError("Schedule must have exactly 5 fields (minute hour day month weekday).")
    if "\n" in command or "\r" in command:
        raise SystemOpError("Command can't contain newlines.")
    if not command.strip():
        raise SystemOpError("Command can't be empty.")

    current = list_cron_jobs()
    current.append(f"{schedule.strip()} {command.strip()}")
    _write_crontab(current)


def delete_cron_job(line_index: int) -> None:
    current = list_cron_jobs()
    if not (0 <= line_index < len(current)):
        raise SystemOpError("Cron job not found.")
    del current[line_index]
    _write_crontab(current)


def _write_crontab(lines: list[str]) -> None:
    content = "\n".join(lines) + ("\n" if lines else "")
    result = subprocess.run(["crontab", "-"], input=content, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemOpError(f"Failed to update crontab: {result.stderr.strip()}")


# ---- Backups ---------------------------------------------------------------
BACKUP_DIR = Path("/var/backups/ds-panel")


def backup_database(db_name: str) -> Path:
    if not is_valid_db_identifier(db_name):
        raise SystemOpError(f"Invalid database name: {db_name!r}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = __import__("datetime").datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    out_path = BACKUP_DIR / f"{db_name}-{stamp}.sql"

    with open(out_path, "wb") as f:
        result = subprocess.run(
            ["mysqldump", "-u", "root", db_name],
            stdout=f,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        out_path.unlink(missing_ok=True)
        raise SystemOpError(f"mysqldump failed: {result.stderr.decode(errors='replace').strip()}")
    return out_path


def backup_site(domain: str) -> Path:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")

    document_root = document_root_for(domain)
    if not document_root.is_dir():
        raise SystemOpError(f"Document root not found: {document_root}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = __import__("datetime").datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    out_path = BACKUP_DIR / f"{domain}-{stamp}.tar.gz"

    _run(["tar", "-czf", str(out_path), "-C", str(document_root.parent), document_root.name])
    return out_path


# ---- Backups browser (list / restore / delete persisted scheduled backups) —
# The scheduled backup script (scripts/run_scheduled_backups.py) writes into
# BACKUP_DIR/scheduled/{sites,databases}/{name}/ — this is the read/restore/
# delete side of that same directory layout for the UI.
SCHEDULED_BACKUP_DIR = BACKUP_DIR / "scheduled"


def _backup_target_dir(target_type: str, target_name: str) -> Path:
    if target_type == "sites":
        if not is_valid_domain(target_name):
            raise SystemOpError(f"Invalid domain: {target_name!r}")
    elif target_type == "databases":
        if not is_valid_db_identifier(target_name):
            raise SystemOpError(f"Invalid database name: {target_name!r}")
    elif target_type == "full":
        if target_name != "server":
            raise SystemOpError(f"Invalid full-backup target: {target_name!r}")
    else:
        raise SystemOpError(f"Invalid backup target type: {target_type!r}")
    return SCHEDULED_BACKUP_DIR / target_type / target_name


def backup_full_server(site_domains: list[str], db_names: list[str]) -> Path:
    """Every panel-managed site's files plus a mysqldump of every
    panel-managed database, all in one zip. Scoped to what the panel itself
    tracks (same reasoning as monitored_services()/CDN/etc being scoped to
    panel-managed resources) rather than literally every file/DB on the box.
    """
    import zipfile

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = __import__("datetime").datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    out_path = BACKUP_DIR / f"full-backup-{stamp}.zip"

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for domain in site_domains:
            root = document_root_for(domain)
            if not root.is_dir():
                continue
            for f in root.rglob("*"):
                if f.is_file():
                    zf.write(f, arcname=str(Path("sites") / domain / f.relative_to(root)))

        for db_name in db_names:
            try:
                dump_path = backup_database(db_name)
            except SystemOpError:
                continue
            zf.write(dump_path, arcname=str(Path("databases") / dump_path.name))
            dump_path.unlink(missing_ok=True)

    return out_path


def list_backups() -> list[dict]:
    """Every persisted scheduled backup file on disk, newest first."""
    results = []
    for target_type in ("sites", "databases", "full"):
        base = SCHEDULED_BACKUP_DIR / target_type
        if not base.is_dir():
            continue
        for target_dir in sorted(base.iterdir()):
            if not target_dir.is_dir():
                continue
            for backup_file in target_dir.iterdir():
                if not backup_file.is_file():
                    continue
                stat = backup_file.stat()
                results.append({
                    "target_type": target_type,
                    "target_name": target_dir.name,
                    "filename": backup_file.name,
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                })
    results.sort(key=lambda b: b["mtime"], reverse=True)
    return results


def get_backup_file_path(target_type: str, target_name: str, filename: str) -> Path:
    target_dir = _backup_target_dir(target_type, target_name)
    # filename comes from a request param — Path.name strips any directory
    # components, same rule as every File Manager filename input, so this
    # can never resolve outside target_dir.
    candidate = target_dir / Path(filename).name
    if not candidate.is_file():
        raise SystemOpError(f"Backup file not found: {filename!r}")
    return candidate


def delete_backup_file(target_type: str, target_name: str, filename: str) -> None:
    get_backup_file_path(target_type, target_name, filename).unlink()


def restore_site_backup(domain: str, filename: str) -> None:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")
    backup_path = get_backup_file_path("sites", domain, filename)
    document_root = document_root_for(domain)
    document_root.mkdir(parents=True, exist_ok=True)

    # The tar was created with `-C {parent} {domain}`, so it already
    # contains a top-level "{domain}/" folder — extract one level up so
    # its contents land back inside document_root, then hand ownership
    # back to www-data (extraction runs as root, same rule as every other
    # panel-driven write).
    _run(["tar", "-xzf", str(backup_path), "-C", str(document_root.parent)])
    own_www_data(document_root)


def restore_database_backup(db_name: str, filename: str) -> None:
    if not is_valid_db_identifier(db_name):
        raise SystemOpError(f"Invalid database name: {db_name!r}")
    backup_path = get_backup_file_path("databases", db_name, filename)

    with open(backup_path, "rb") as f:
        result = subprocess.run(
            ["mysql", "-u", "root", db_name],
            stdin=f,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        raise SystemOpError(f"mysql restore failed: {result.stderr.decode(errors='replace').strip()}")


# ---- Node.js app hosting (pm2) ---------------------------------------------
NODE_PORT_RANGE_START = 3001
NODE_PORT_RANGE_END = 3999


def allocate_node_port(existing_ports: list[int]) -> int:
    """Picks the first free port in the Node app range that isn't already
    assigned to another site. `existing_ports` is the caller's current
    `sites.node_port` column values — kept out of this module so system_ops
    stays free of any direct DB dependency.
    """
    taken = set(existing_ports)
    for port in range(NODE_PORT_RANGE_START, NODE_PORT_RANGE_END + 1):
        if port not in taken:
            return port
    raise SystemOpError("No free port available in the Node.js app range.")


# Uses __TOKEN__ placeholders + str.replace() instead of str.format() —
# PLACEHOLDER_HTML is full of literal `{`/`}` from its inline CSS, which
# would collide with .format()'s field syntax if the two were combined.
NODE_APP_TEMPLATE = """const http = require('http');
const port = process.env.PORT || __NODE_PORT__;
const page = __PAGE_JSON__;

http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(page);
}).listen(port, () => console.log(`listening on ${port}`));
"""


def scaffold_node_app(domain: str, document_root: Path, node_port: int) -> None:
    """Drops a minimal starter server.js so a freshly-added Node site has
    something for pm2 to run immediately — same idea as the plain
    index.html placeholder create_site_directory() writes for PHP sites,
    and serves the identical "Under Construction" page as that placeholder.
    """
    server_js = document_root / "server.js"
    if not server_js.exists():
        html = PLACEHOLDER_HTML.format(domain=domain)
        content = (
            NODE_APP_TEMPLATE
            .replace("__NODE_PORT__", str(node_port))
            .replace("__PAGE_JSON__", json.dumps(html))
        )
        server_js.write_text(content, encoding="utf-8")
        own_www_data(server_js)


def _pm2_process_name(domain: str) -> str:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")
    return f"dearsoft-{domain}"


def start_node_app(domain: str, document_root: Path, node_port: int) -> None:
    name = _pm2_process_name(domain)
    entry = document_root / "server.js"
    if not entry.is_file():
        raise SystemOpError(f"No server.js found at {entry}")

    # Idempotent: if a process with this name already exists (e.g. a
    # panel-restart re-applying state), replace it cleanly instead of
    # pm2 refusing a duplicate start.
    subprocess.run(["pm2", "delete", name], capture_output=True, text=True)
    _run(
        [
            "pm2", "start", str(entry),
            "--name", name,
            "--cwd", str(document_root),
        ],
        timeout=60,
    )
    _run(["pm2", "save"], timeout=30)


def stop_node_app(domain: str) -> None:
    name = _pm2_process_name(domain)
    # Not an error if it was never running (e.g. start failed earlier) —
    # deleting a site should always succeed at cleanup, not get stuck.
    subprocess.run(["pm2", "delete", name], capture_output=True, text=True)
    subprocess.run(["pm2", "save"], capture_output=True, text=True)


# ---- One-click app installer (Phase 7) -------------------------------------
# Downloads the real upstream release and extracts it into an existing
# site's document root — same "reuse proven tools, don't reimplement them"
# rule as phpMyAdmin. The app's own first-run web wizard (wp-admin/install.php,
# OpenCart's /install/) is left for the user to finish, exactly like every
# other one-click installer does under the hood; we only automate the tedious
# download/extract/database/config-file part.
WORDPRESS_URL = "https://wordpress.org/latest.zip"
OPENCART_VERSIONS = {
    "4.1.0.4": "https://github.com/opencart/opencart/releases/download/4.1.0.4/opencart-4.1.0.4.zip",
    "4.0.2.3": "https://github.com/opencart/opencart/releases/download/4.0.2.3/opencart-4.0.2.3.zip",
    "3.0.5.0": "https://github.com/opencart/opencart/releases/download/3.0.5.0/opencart-3.0.5.0.zip",
}
DEFAULT_OPENCART_VERSION = "4.1.0.4"


def _download_and_extract(url: str, timeout: int = 180) -> Path:
    import tempfile

    tmp_dir = Path(tempfile.mkdtemp(prefix="dearsoft-appinstall-"))
    zip_path = tmp_dir / "app.zip"
    _run(["curl", "-fsSL", url, "-o", str(zip_path)], timeout=timeout)
    _run(["unzip", "-oq", str(zip_path), "-d", str(tmp_dir)], timeout=timeout)
    zip_path.unlink(missing_ok=True)
    return tmp_dir


def _move_contents(src_dir: Path, document_root: Path) -> None:
    """Moves every item inside src_dir into document_root, overwriting
    anything already there (e.g. the placeholder index.html). Pure Python
    shutil, deliberately not a subprocess call — nothing here is
    user-controlled input, but moving files is simpler and safer done
    directly than by shelling out to `mv`/`cp`.
    """
    import shutil

    for item in src_dir.iterdir():
        dest = document_root / item.name
        if dest.exists():
            if dest.is_dir():
                shutil.rmtree(dest)
            else:
                dest.unlink()
        shutil.move(str(item), str(dest))


def install_wordpress(domain: str, document_root: Path, db_name: str, db_user: str, db_password: str) -> None:
    import shutil

    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")

    tmp_dir = _download_and_extract(WORDPRESS_URL)
    try:
        extracted = tmp_dir / "wordpress"
        if not extracted.is_dir():
            raise SystemOpError("Unexpected WordPress archive layout.")
        _move_contents(extracted, document_root)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    _write_wp_config(document_root, db_name, db_user, db_password)
    subprocess.run(["chown", "-R", "www-data:www-data", str(document_root)], capture_output=True)


def _write_wp_config(document_root: Path, db_name: str, db_user: str, db_password: str) -> None:
    import secrets
    import string

    sample = document_root / "wp-config-sample.php"
    if not sample.is_file():
        raise SystemOpError("wp-config-sample.php not found — WordPress extraction may have failed.")

    text = sample.read_text(encoding="utf-8")
    text = text.replace("database_name_here", db_name, 1)
    text = text.replace("username_here", db_user, 1)
    # Backslash-escape any quote so a generated password can never break out
    # of the single-quoted PHP string literal it's being placed into.
    text = text.replace("password_here", db_password.replace("\\", "\\\\").replace("'", "\\'"), 1)

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    for _ in range(8):  # AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY + the 4 _SALT variants
        random_key = "".join(secrets.choice(alphabet) for _ in range(64))
        text = text.replace("put your unique phrase here", random_key, 1)

    (document_root / "wp-config.php").write_text(text, encoding="utf-8")
    sample.unlink(missing_ok=True)


def _find_opencart_upload_dir(tmp_dir: Path) -> Path:
    """OpenCart's official release zip has "upload/" directly at the top
    level, but a couple of alternate/self-hosted archive shapes wrap
    everything in one extra folder first (e.g. a GitHub source archive
    named "opencart-4.0.2.3/upload/"). Check both shapes rather than
    assuming one, since guessing wrong here is exactly what raised the
    "Unexpected archive layout" error on the first version of this.
    """
    direct = tmp_dir / "upload"
    if direct.is_dir():
        return direct

    top_level_dirs = [p for p in tmp_dir.iterdir() if p.is_dir()]
    if len(top_level_dirs) == 1:
        nested = top_level_dirs[0] / "upload"
        if nested.is_dir():
            return nested

    raise SystemOpError(
        "Unexpected OpenCart archive layout — couldn't find an 'upload' folder "
        "in the downloaded release."
    )


def install_opencart(domain: str, document_root: Path, version: str = DEFAULT_OPENCART_VERSION) -> None:
    import shutil

    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")
    if version not in OPENCART_VERSIONS:
        raise SystemOpError(f"Unsupported OpenCart version: {version!r}")

    tmp_dir = _download_and_extract(OPENCART_VERSIONS[version])
    try:
        upload_dir = _find_opencart_upload_dir(tmp_dir)
        _move_contents(upload_dir, document_root)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # OpenCart 4.x depends on Composer packages (Twig, AWS SDK, Guzzle, …)
    # for its admin theme — GitHub's release zip only ships composer.json,
    # not the actual vendor/ library code (that's excluded like any
    # .gitignored path), so the admin panel 500s with "Class ... not
    # found" until `composer install` actually pulls them in. This step
    # needs outbound internet access on the server (packagist.org).
    composer_json = document_root / "system" / "storage" / "composer.json"
    if composer_json.is_file():
        _run(
            [
                "composer", "install",
                "--no-dev", "--no-interaction", "--optimize-autoloader",
                f"--working-dir={composer_json.parent}",
            ],
            timeout=180,
        )

    # OpenCart's own web installer writes config.php / admin/config.php and
    # needs the whole tree writable by the PHP process to do it.
    subprocess.run(["chown", "-R", "www-data:www-data", str(document_root)], capture_output=True)


JOOMLA_URL = "https://downloads.joomla.org/us/technical-requirements/joomla5/joomla_5-latest-full-package-zip"
OWNCLOUD_URL = "https://download.owncloud.com/server/stable/owncloud-complete-latest.zip"


def install_joomla(domain: str, document_root: Path) -> None:
    import shutil

    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")

    tmp_dir = _download_and_extract(JOOMLA_URL)
    try:
        _move_contents(tmp_dir, document_root)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Joomla's own web installer (/installation/) writes configuration.php
    # itself and needs the tree writable to do it, same as OpenCart's flow.
    subprocess.run(["chown", "-R", "www-data:www-data", str(document_root)], capture_output=True)


def install_owncloud(domain: str, document_root: Path) -> None:
    import shutil

    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")

    tmp_dir = _download_and_extract(OWNCLOUD_URL, timeout=300)
    try:
        extracted = tmp_dir / "owncloud"
        if not extracted.is_dir():
            raise SystemOpError("Unexpected ownCloud archive layout.")
        _move_contents(extracted, document_root)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    subprocess.run(["chown", "-R", "www-data:www-data", str(document_root)], capture_output=True)


def install_laravel(domain: str, document_root: Path) -> Path:
    """Unlike the zip-download installers above, Laravel doesn't ship a
    ready-made release archive — `composer create-project` is the real
    upstream install method, so that's what this shells out to (this is
    exactly the "needs a live composer create-project run" case the
    original app_store.py docstring flagged as deferred). Installs into
    document_root itself, but the actual web root nginx must be pointed at
    is document_root/public — the caller is responsible for calling
    write_nginx_vhost(..., document_root_override=the returned path).
    """
    import shutil
    import tempfile

    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")

    tmp_dir = Path(tempfile.mkdtemp(prefix="dearsoft-appinstall-"))
    try:
        project_dir = tmp_dir / "app"
        _run(
            ["composer", "create-project", "--prefer-dist", "--no-interaction", "laravel/laravel", str(project_dir)],
            timeout=300,
        )
        if not project_dir.is_dir():
            raise SystemOpError("Laravel project creation appears to have failed — no project directory produced.")
        _move_contents(project_dir, document_root)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    for rel in ("storage", "bootstrap/cache"):
        target = document_root / rel
        if target.is_dir():
            subprocess.run(["chmod", "-R", "775", str(target)], capture_output=True)

    subprocess.run(["chown", "-R", "www-data:www-data", str(document_root)], capture_output=True)
    return document_root / "public"


def issue_certificate(domain: str, admin_email: str, extra_domains: list[str] | None = None) -> None:
    """certbot handles rewriting the vhost to add the SSL server block and
    the port-80-to-443 redirect itself (--nginx plugin) — we don't hand-roll
    any of the TLS/redirect config, only the plain-HTTP vhost above.

    extra_domains lets one certificate cover a site's domain aliases too
    (certbot's -d can repeat) — required whenever aliases are added to an
    already-SSL-enabled site, via --expand, so the existing cert's SAN
    list grows instead of failing on "already have a cert for this name".
    """
    for name in [domain] + list(extra_domains or []):
        if not is_valid_domain(name):
            raise SystemOpError(f"Invalid domain: {name!r}")

    args = ["certbot", "--nginx", "-d", domain]
    for extra in extra_domains or []:
        args += ["-d", extra]
    args += ["--non-interactive", "--agree-tos", "-m", admin_email, "--redirect", "--expand"]

    _run(args, timeout=120)


# ---- Logs viewer -------------------------------------------------------
# Every source here is a fixed, allow-listed entry — never a user-supplied
# path. This is the same allow-list discipline as everywhere else in this
# file: the set of readable logs is closed, not derived from request input.
def _php_fpm_log_sources() -> dict:
    return {
        f"php{v}_fpm": {"label": f"PHP {v}-FPM", "type": "file", "path": f"/var/log/php{v}-fpm.log"}
        for v in ALLOWED_PHP_VERSIONS
    }


def log_sources() -> dict:
    sources = {
        "nginx_error": {"label": "Nginx Error Log", "type": "file", "path": "/var/log/nginx/error.log"},
        "nginx_access": {"label": "Nginx Access Log", "type": "file", "path": "/var/log/nginx/access.log"},
        "panel": {"label": "DS Panel Service Log", "type": "journal", "unit": "ds-panel"},
        "mysql_error": {"label": "MySQL/MariaDB Error Log", "type": "file", "path": "/var/log/mysql/error.log"},
    }
    sources.update(_php_fpm_log_sources())
    return sources


def tail_log(source_key: str, lines: int = 200, grep: str = "") -> str:
    sources = log_sources()
    source = sources.get(source_key)
    if not source:
        raise SystemOpError(f"Unknown log source: {source_key!r}")

    lines = max(1, min(lines, 2000))  # a runaway line count is a self-inflicted DoS on the panel itself

    if source["type"] == "journal":
        result = subprocess.run(
            ["journalctl", "-u", source["unit"], "-n", str(lines), "--no-pager"],
            capture_output=True, text=True, timeout=15,
        )
        text = result.stdout
    else:
        path = Path(source["path"])
        if not path.is_file():
            return f"(log file not found yet: {path})"
        result = subprocess.run(["tail", "-n", str(lines), str(path)], capture_output=True, text=True, timeout=15)
        text = result.stdout

    if grep:
        # Plain substring filter, not a regex — a log viewer's search box
        # should never be able to smuggle a hostile pattern into `grep -E`.
        text = "\n".join(line for line in text.splitlines() if grep.lower() in line.lower())

    return text


# ---- SSH Access management --------------------------------------------
# Manages authorized_keys only — deliberately never touches sshd_config
# (port, PasswordAuthentication, PermitRootLogin, etc.). A bad edit there
# risks locking out SSH entirely with no recovery path except the cloud
# provider's own serial/browser console, which is a much bigger blast
# radius than this feature is worth. Adding/removing individual public
# keys is the safe 90% of "SSH Access" a panel should offer.
SSH_KEY_TYPES = ("ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521")


def list_ssh_users() -> list[dict]:
    """Every real login account with a home directory — root plus anything
    in /home. Deliberately not every line of /etc/passwd (system service
    accounts like www-data, mysql, etc. aren't SSH login targets).
    """
    import pwd

    users = []
    for entry in pwd.getpwall():
        is_root = entry.pw_uid == 0
        is_home_user = entry.pw_uid >= 1000 and Path(entry.pw_dir).parent == Path("/home")
        if not (is_root or is_home_user):
            continue
        ssh_dir = Path(entry.pw_dir) / ".ssh"
        auth_keys = ssh_dir / "authorized_keys"
        users.append({
            "username": entry.pw_name,
            "home": entry.pw_dir,
            "key_count": len(_read_authorized_keys(auth_keys)) if auth_keys.is_file() else 0,
        })
    return sorted(users, key=lambda u: (u["username"] != "root", u["username"]))


def _authorized_keys_path(username: str) -> Path:
    import pwd

    try:
        entry = pwd.getpwnam(username)
    except KeyError:
        raise SystemOpError(f"No such system user: {username!r}")
    return Path(entry.pw_dir) / ".ssh" / "authorized_keys"


def _read_authorized_keys(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def list_ssh_keys(username: str) -> list[dict]:
    path = _authorized_keys_path(username)
    keys = []
    for i, line in enumerate(_read_authorized_keys(path)):
        parts = line.split()
        key_type = parts[0] if parts and parts[0] in SSH_KEY_TYPES else "unknown"
        comment = parts[2] if len(parts) >= 3 else ""
        fingerprint = parts[1][-24:] if len(parts) >= 2 else line[-24:]
        keys.append({"index": i, "type": key_type, "fingerprint": fingerprint, "comment": comment, "raw": line})
    return keys


def add_ssh_key(username: str, key_line: str) -> None:
    key_line = key_line.strip()
    if "\n" in key_line or "\r" in key_line:
        raise SystemOpError("Paste exactly one key — no line breaks.")
    parts = key_line.split()
    if len(parts) < 2 or parts[0] not in SSH_KEY_TYPES:
        raise SystemOpError(
            "Doesn't look like a valid public key line — it should start with "
            "ssh-rsa, ssh-ed25519, etc. (this is the .pub file's content, not the private key)."
        )

    path = _authorized_keys_path(username)
    existing = _read_authorized_keys(path)
    if any(line.split()[1] == parts[1] for line in existing if len(line.split()) >= 2):
        raise SystemOpError("This exact key is already authorized for this user.")

    path.parent.mkdir(mode=0o700, exist_ok=True)
    existing.append(key_line)
    path.write_text("\n".join(existing) + "\n", encoding="utf-8")
    path.chmod(0o600)
    path.parent.chmod(0o700)
    _chown_to_user(username, path.parent)


def delete_ssh_key(username: str, key_index: int) -> None:
    path = _authorized_keys_path(username)
    existing = _read_authorized_keys(path)
    if not (0 <= key_index < len(existing)):
        raise SystemOpError("Key not found.")
    if len(existing) <= 1:
        raise SystemOpError(
            "Refusing to remove the last key for this user — that would lock out SSH access entirely. "
            "Add a replacement key first."
        )
    del existing[key_index]
    path.write_text("\n".join(existing) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _chown_to_user(username: str, path: Path) -> None:
    subprocess.run(["chown", "-R", f"{username}:{username}", str(path)], capture_output=True)


# ---- Monitor -----------------------------------------------------------
# Fixed, allow-listed set of services — same discipline as log_sources():
# never derived from request input, just a closed list of the daemons this
# panel actually depends on or manages.
MONITORED_UNITS = [
    ("ds-panel", "DS Panel"),
    ("nginx", "Nginx"),
    ("mariadb", "MariaDB / MySQL"),
    ("cron", "Cron"),
] + [(f"php{v}-fpm", f"PHP {v}-FPM") for v in ALLOWED_PHP_VERSIONS]
MONITORED_UNIT_NAMES = {unit for unit, _label in MONITORED_UNITS}


def monitored_services() -> list[dict]:
    results = []
    for unit, label in MONITORED_UNITS:
        result = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=10)
        results.append({"unit": unit, "label": label, "active": result.stdout.strip() == "active"})
    return results


def restart_service(unit: str) -> None:
    # Allow-listed to the monitored units, MINUS ds-panel itself — the
    # AI Assistant must never be able to restart an arbitrary systemd unit
    # just because a chat message asked for one, and restarting the panel's
    # own service would kill the very request handling that restart.
    if unit not in MONITORED_UNIT_NAMES or unit == "ds-panel":
        raise SystemOpError(f"{unit!r} isn't a service the AI Assistant can restart.")
    _run(["systemctl", "restart", unit], timeout=30)


def get_uptime() -> str:
    with open("/proc/uptime") as f:
        seconds = float(f.read().split()[0])
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def get_load_averages() -> dict:
    with open("/proc/loadavg") as f:
        one, five, fifteen = f.read().split()[:3]
    return {"1min": float(one), "5min": float(five), "15min": float(fifteen)}


def get_top_processes(limit: int = 10) -> list[dict]:
    result = subprocess.run(
        ["ps", "-eo", "pid,comm,%cpu,%mem", "--sort=-%cpu", "--no-headers"],
        capture_output=True, text=True, timeout=10,
    )
    processes = []
    for line in result.stdout.splitlines()[:limit]:
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        processes.append({"pid": parts[0], "name": parts[1], "cpu": parts[2], "mem": parts[3]})
    return processes


# ---- Docker --------------------------------------------------------------
# A thin wrapper over the real `docker` CLI — same "reuse proven tools,
# don't reimplement them" rule as phpMyAdmin/certbot/crontab elsewhere in
# this file. Container IDs come back from `docker ps` itself (never typed
# by a user into a form), so they're trusted as opaque tokens rather than
# needing a domain-style allow-list regex — but the argument-list-only
# subprocess rule still applies without exception.
CONTAINER_ID_RE = re.compile(r"^[a-f0-9]{12,64}$")


def _validate_container_id(container_id: str) -> None:
    if not CONTAINER_ID_RE.match(container_id):
        raise SystemOpError(f"Invalid container id: {container_id!r}")


def docker_available() -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", "docker"], capture_output=True).returncode == 0


def list_containers() -> list[dict]:
    result = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.Ports}}"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise SystemOpError(f"docker ps failed: {result.stderr.strip()}")

    containers = []
    for line in result.stdout.splitlines():
        parts = line.split("|", 4)
        if len(parts) < 5:
            continue
        container_id, image, name, status, ports = parts
        containers.append({
            "id": container_id,
            "image": image,
            "name": name,
            "status": status,
            "ports": ports,
            "running": status.lower().startswith("up"),
        })
    return containers


def container_action(container_id: str, action: str) -> None:
    _validate_container_id(container_id)
    if action not in ("start", "stop", "restart"):
        raise SystemOpError(f"Invalid container action: {action!r}")
    _run(["docker", action, container_id], timeout=60)


def remove_container(container_id: str) -> None:
    _validate_container_id(container_id)
    _run(["docker", "rm", "-f", container_id], timeout=30)


def container_logs(container_id: str, lines: int = 200) -> str:
    _validate_container_id(container_id)
    lines = max(1, min(lines, 2000))
    result = subprocess.run(
        ["docker", "logs", "--tail", str(lines), container_id],
        capture_output=True, text=True, timeout=15,
    )
    return (result.stdout or "") + (result.stderr or "")


# ---- Mail Server (Postfix + Dovecot, virtual mailboxes) --------------------
# Flat-file virtual mailboxes (no MySQL backend) — install.sh wires Postfix's
# virtual_mailbox_domains at /etc/postfix/vhosts (plain list, no postmap
# needed — Postfix supports that file directly) and virtual_mailbox_maps at
# /etc/postfix/vmailbox (a hash: map, DOES need `postmap` after every edit).
# Dovecot authenticates against /etc/dovecot/dearsoft-users, a passwd-file
# with SHA512-CRYPT hashes produced by `doveadm pw`.
#
# IMPORTANT, surfaced in the UI too: most cloud providers (GCP included)
# block outbound traffic on port 25 by default to fight spam — this means
# RECEIVING mail here works fine (nothing blocks inbound 25), but SENDING
# to external mail servers over raw SMTP (25) will silently fail to
# deliver until that's unblocked (a support request to the cloud provider)
# or a smarthost/relay is configured. Port 587 (authenticated submission,
# what real mail clients use) is unaffected by that specific restriction,
# but many providers rate-limit or also block it for fresh accounts —
# verify this actually works for you before relying on it for anything
# important.
MAIL_VHOSTS_FILE = Path("/etc/postfix/vhosts")
MAIL_VMAILBOX_FILE = Path("/etc/postfix/vmailbox")
MAIL_DOVECOT_USERS_FILE = Path("/etc/dovecot/dearsoft-users")
MAIL_BASE_DIR = Path("/var/mail/vhosts")

EMAIL_ADDR_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def mail_server_available() -> bool:
    return (
        subprocess.run(["systemctl", "is-active", "--quiet", "postfix"], capture_output=True).returncode == 0
        and subprocess.run(["systemctl", "is-active", "--quiet", "dovecot"], capture_output=True).returncode == 0
    )


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def list_mail_domains() -> list[str]:
    return sorted(_read_lines(MAIL_VHOSTS_FILE))


def list_mailboxes() -> list[dict]:
    """Parses /etc/postfix/vmailbox — each line is "email  domain/user/"."""
    mailboxes = []
    for line in _read_lines(MAIL_VMAILBOX_FILE):
        parts = line.split(None, 1)
        if len(parts) == 2:
            mailboxes.append({"email": parts[0], "domain": parts[0].split("@", 1)[1]})
    return sorted(mailboxes, key=lambda m: m["email"])


def add_mail_domain(domain: str) -> None:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")
    domains = _read_lines(MAIL_VHOSTS_FILE)
    if domain in domains:
        raise SystemOpError(f"'{domain}' is already a mail domain.")
    domains.append(domain)
    MAIL_VHOSTS_FILE.write_text("\n".join(domains) + "\n", encoding="utf-8")
    (MAIL_BASE_DIR / domain).mkdir(parents=True, exist_ok=True)
    subprocess.run(["chown", "-R", "vmail:mail", str(MAIL_BASE_DIR / domain)], capture_output=True)
    _run(["systemctl", "reload", "postfix"])


def remove_mail_domain(domain: str) -> None:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")
    still_used = [m for m in list_mailboxes() if m["domain"] == domain]
    if still_used:
        raise SystemOpError(
            f"Can't remove '{domain}' — {len(still_used)} mailbox(es) still use it. Delete those first."
        )
    domains = [d for d in _read_lines(MAIL_VHOSTS_FILE) if d != domain]
    MAIL_VHOSTS_FILE.write_text("\n".join(domains) + ("\n" if domains else ""), encoding="utf-8")
    _run(["systemctl", "reload", "postfix"])


def add_mailbox(email: str, password: str) -> None:
    email = email.strip().lower()
    if not EMAIL_ADDR_RE.match(email):
        raise SystemOpError(f"Invalid email address: {email!r}")
    if not password or len(password) < 8:
        raise SystemOpError("Password must be at least 8 characters.")

    domain = email.split("@", 1)[1]
    if domain not in list_mail_domains():
        raise SystemOpError(f"'{domain}' isn't a registered mail domain yet — add the domain first.")
    if any(m["email"] == email for m in list_mailboxes()):
        raise SystemOpError(f"Mailbox '{email}' already exists.")

    local_part = email.split("@", 1)[0]

    hash_result = subprocess.run(
        ["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password],
        capture_output=True, text=True, timeout=15,
    )
    if hash_result.returncode != 0:
        raise SystemOpError(f"Password hashing failed: {hash_result.stderr.strip()}")
    password_hash = hash_result.stdout.strip()

    vmailbox_lines = _read_lines(MAIL_VMAILBOX_FILE)
    vmailbox_lines.append(f"{email}\t{domain}/{local_part}/")
    MAIL_VMAILBOX_FILE.write_text("\n".join(vmailbox_lines) + "\n", encoding="utf-8")
    _run(["postmap", str(MAIL_VMAILBOX_FILE)])

    users_lines = _read_lines(MAIL_DOVECOT_USERS_FILE)
    users_lines.append(f"{email}:{password_hash}")
    MAIL_DOVECOT_USERS_FILE.write_text("\n".join(users_lines) + "\n", encoding="utf-8")
    MAIL_DOVECOT_USERS_FILE.chmod(0o640)
    subprocess.run(["chown", "root:dovecot", str(MAIL_DOVECOT_USERS_FILE)], capture_output=True)

    mailbox_dir = MAIL_BASE_DIR / domain / local_part
    mailbox_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["chown", "-R", "vmail:mail", str(mailbox_dir)], capture_output=True)

    _run(["systemctl", "reload", "postfix"])
    _run(["systemctl", "reload", "dovecot"])


def remove_mailbox(email: str) -> None:
    email = email.strip().lower()

    vmailbox_lines = [line for line in _read_lines(MAIL_VMAILBOX_FILE) if not line.startswith(f"{email}\t")]
    MAIL_VMAILBOX_FILE.write_text("\n".join(vmailbox_lines) + ("\n" if vmailbox_lines else ""), encoding="utf-8")
    _run(["postmap", str(MAIL_VMAILBOX_FILE)])

    users_lines = [line for line in _read_lines(MAIL_DOVECOT_USERS_FILE) if not line.startswith(f"{email}:")]
    MAIL_DOVECOT_USERS_FILE.write_text("\n".join(users_lines) + ("\n" if users_lines else ""), encoding="utf-8")

    _run(["systemctl", "reload", "postfix"])


# ---- WAF (ModSecurity for Nginx + OWASP CRS) -------------------------------
# install.sh installs the packages and writes the config files but leaves
# the WAF globally OFF (an empty toggle file) and, even once turned on,
# defaults its rule engine to DetectionOnly (logs what it would have
# blocked, doesn't actually block) — see install.sh's comment for why.
# This section is just the on/off + mode switch the WAF page uses; the
# actual rule set is the untouched upstream OWASP Core Rule Set.
WAF_MODSEC_CONF = Path("/etc/nginx/modsec/modsecurity.conf")
WAF_TOGGLE_CONF = Path("/etc/nginx/conf.d/modsecurity-toggle.conf")
WAF_AUDIT_LOG = Path("/var/log/nginx/modsec_audit.log")

WAF_ACTIVATION_DIRECTIVES = (
    "modsecurity on;\n"
    "modsecurity_rules_file /etc/nginx/modsec/main.conf;\n"
)


def waf_installed() -> bool:
    return WAF_MODSEC_CONF.is_file() and WAF_TOGGLE_CONF.is_file()


def get_waf_status() -> dict:
    enabled = WAF_TOGGLE_CONF.is_file() and "modsecurity on" in WAF_TOGGLE_CONF.read_text(encoding="utf-8")
    mode = "DetectionOnly"
    if WAF_MODSEC_CONF.is_file():
        for line in WAF_MODSEC_CONF.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("SecRuleEngine"):
                mode = line.split()[-1]
                break
    return {"enabled": enabled, "mode": mode}


def set_waf_enabled(enabled: bool) -> None:
    if not waf_installed():
        raise SystemOpError("WAF isn't installed — re-run install.sh.")
    content = (
        WAF_ACTIVATION_DIRECTIVES if enabled
        else "# Managed by DS Panel's WAF page — do not edit directly.\n"
    )
    WAF_TOGGLE_CONF.write_text(content, encoding="utf-8")
    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])


def set_waf_mode(mode: str) -> None:
    if mode not in ("DetectionOnly", "On"):
        raise SystemOpError(f"Invalid WAF mode: {mode!r}")
    if not WAF_MODSEC_CONF.is_file():
        raise SystemOpError("WAF isn't installed — re-run install.sh.")

    lines = WAF_MODSEC_CONF.read_text(encoding="utf-8").splitlines()
    new_lines = [
        f"SecRuleEngine {mode}" if line.strip().startswith("SecRuleEngine") else line
        for line in lines
    ]
    WAF_MODSEC_CONF.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])


def waf_recent_events(lines: int = 100) -> str:
    if not WAF_AUDIT_LOG.is_file():
        return "(no WAF events logged yet)"
    result = subprocess.run(["tail", "-n", str(lines), str(WAF_AUDIT_LOG)], capture_output=True, text=True, timeout=15)
    return result.stdout or "(no WAF events logged yet)"


def install_waf() -> None:
    """On-demand WAF install, triggered from the App Store (not bundled into
    install.sh — not every server wants ModSecurity + the CRS running).
    Installs the packages, writes the config files DetectionOnly/globally-off
    by default (same safety reasoning as before), and reloads nginx.
    """
    if waf_installed():
        return
    _run(["apt-get", "install", "-y", "-qq", "libnginx-mod-http-modsecurity", "modsecurity-crs"], timeout=180)

    modsec_dir = Path("/etc/nginx/modsec")
    modsec_dir.mkdir(parents=True, exist_ok=True)

    if not WAF_MODSEC_CONF.is_file():
        WAF_MODSEC_CONF.write_text(
            "SecRuleEngine DetectionOnly\n"
            "SecRequestBodyAccess On\n"
            "SecResponseBodyAccess Off\n"
            "SecAuditEngine RelevantOnly\n"
            "SecAuditLog /var/log/nginx/modsec_audit.log\n",
            encoding="utf-8",
        )

    main_conf = modsec_dir / "main.conf"
    if not main_conf.is_file():
        # The Ubuntu modsecurity-crs package installs its setup config
        # already-active (not a .example template needing a copy first) at
        # /etc/modsecurity/crs/crs-setup.conf — confirmed via `dpkg -L
        # modsecurity-crs` after the earlier /usr/share/modsecurity-crs/
        # crs-setup.conf.example path turned out not to exist at all and
        # broke `nginx -t`.
        main_conf.write_text(
            "Include /etc/nginx/modsec/modsecurity.conf\n"
            "Include /etc/modsecurity/crs/crs-setup.conf\n"
            "Include /usr/share/modsecurity-crs/rules/*.conf\n",
            encoding="utf-8",
        )

    if not WAF_TOGGLE_CONF.is_file():
        WAF_TOGGLE_CONF.write_text("# Managed by DS Panel's WAF page — do not edit directly.\n", encoding="utf-8")

    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])


# ---- Apache (available as a second web server alongside nginx) -------------
def apache_installed() -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", "apache2"], capture_output=True).returncode == 0


def install_apache() -> None:
    """On-demand Apache install, triggered from the App Store. Runs on port
    8080 so it coexists with nginx (which owns 80/443) without conflict —
    it's offered as a second web server, not a replacement.
    """
    if apache_installed():
        return
    _run(["apt-get", "install", "-y", "-qq", "apache2"], timeout=180)

    ports_conf = Path("/etc/apache2/ports.conf")
    if ports_conf.is_file():
        text = ports_conf.read_text(encoding="utf-8")
        if "Listen 8080" not in text:
            ports_conf.write_text(text.replace("Listen 80\n", "Listen 8080\n"), encoding="utf-8")

    default_site = Path("/etc/apache2/sites-available/000-default.conf")
    if default_site.is_file():
        text = default_site.read_text(encoding="utf-8")
        default_site.write_text(text.replace("<VirtualHost *:80>", "<VirtualHost *:8080>"), encoding="utf-8")

    _run(["systemctl", "enable", "--quiet", "--now", "apache2"])
    subprocess.run(["ufw", "allow", "8080/tcp"], capture_output=True)


# ---- CDN (Cloudflare + Tencent EdgeOne) — purge-cache + status only -------
# v1 scope, confirmed with the user: connect an existing zone via API
# credentials and offer a "Purge Cache" button + status pill. No DNS record
# management, no proxy on/off toggle — those are real API surface but a
# bigger build than this pass covers.
def cloudflare_zone_status(zone_id: str, api_token: str) -> dict:
    resp = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}",
        headers={"Authorization": f"Bearer {api_token}"},
        timeout=20,
    )
    data = resp.json()
    if not data.get("success"):
        raise SystemOpError(f"Cloudflare zone lookup failed: {data.get('errors')}")
    result = data["result"]
    return {"name": result.get("name"), "status": result.get("status")}


def cloudflare_purge_cache(zone_id: str, api_token: str) -> None:
    resp = requests.post(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache",
        headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
        json={"purge_everything": True},
        timeout=20,
    )
    data = resp.json()
    if not data.get("success"):
        raise SystemOpError(f"Cloudflare purge failed: {data.get('errors')}")


def _tencent_signed_request(secret_id: str, secret_key: str, action: str, payload: dict,
                             service: str = "teo", version: str = "2022-09-01") -> dict:
    """TC3-HMAC-SHA256 request signing for one Tencent Cloud API call — see
    Tencent Cloud's own "signature v3" spec. Implemented directly rather than
    pulling in the tencentcloud-sdk-python package, since only this single
    action (purge cache) is needed here.
    """
    host = f"{service}.tencentcloudapi.com"
    timestamp = int(time.time())
    date = time.strftime("%Y-%m-%d", time.gmtime(timestamp))
    payload_str = json.dumps(payload)

    canonical_request = (
        "POST\n/\n\n"
        f"content-type:application/json\nhost:{host}\nx-tc-action:{action.lower()}\n\n"
        "content-type;host;x-tc-action\n"
        f"{hashlib.sha256(payload_str.encode('utf-8')).hexdigest()}"
    )
    credential_scope = f"{date}/{service}/tc3_request"
    string_to_sign = (
        "TC3-HMAC-SHA256\n"
        f"{timestamp}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    def _hm(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _hm(("TC3" + secret_key).encode("utf-8"), date)
    k_service = _hm(k_date, service)
    k_signing = _hm(k_service, "tc3_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (
        f"TC3-HMAC-SHA256 Credential={secret_id}/{credential_scope}, "
        "SignedHeaders=content-type;host;x-tc-action, "
        f"Signature={signature}"
    )
    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version,
    }
    resp = requests.post(f"https://{host}", headers=headers, data=payload_str, timeout=20)
    data = resp.json()
    if "Response" not in data or "Error" in data.get("Response", {}):
        raise SystemOpError(f"Tencent EdgeOne API error: {data}")
    return data["Response"]


def edgeone_zone_status(secret_id: str, secret_key: str, zone_id: str) -> dict:
    resp = _tencent_signed_request(secret_id, secret_key, "DescribeZones", {"Filters": [{"Name": "zone-id", "Values": [zone_id]}]})
    zones = resp.get("Zones") or []
    if not zones:
        raise SystemOpError("EdgeOne zone not found — check the Zone ID.")
    zone = zones[0]
    return {"name": zone.get("ZoneName"), "status": zone.get("Status")}


def edgeone_purge_cache(secret_id: str, secret_key: str, zone_id: str) -> None:
    _tencent_signed_request(secret_id, secret_key, "CreatePurgeTask", {"ZoneId": zone_id, "Type": "purge_all"})


# ---- Node.js Version Manager -------------------------------------------
# install.sh already installs one system Node.js (LTS, via NodeSource) for
# Node site hosting — this adds the ability to install and switch between
# OTHER major versions system-wide, for sites that need a specific one.
# Built on "n" (tj/n), a small well-known Node version manager, rather than
# reimplementing version download/switching.
NODE_VERSIONS = ["18", "20", "22"]


def node_manager_installed() -> bool:
    return subprocess.run(["which", "n"], capture_output=True).returncode == 0


def install_node_manager() -> None:
    if node_manager_installed():
        return
    _run(["npm", "install", "-g", "n"], timeout=120)


def current_node_version() -> str:
    result = subprocess.run(["node", "-v"], capture_output=True, text=True, timeout=10)
    return result.stdout.strip() or "unknown"


def installed_node_versions() -> list[str]:
    if not node_manager_installed():
        return []
    result = subprocess.run(["n", "ls"], capture_output=True, text=True, timeout=15)
    versions = []
    for line in result.stdout.splitlines():
        line = line.strip().lstrip("*").strip()
        if line.startswith("node/"):
            versions.append(line.split("/")[-1])
    return versions


def switch_node_version(version: str) -> None:
    if version not in NODE_VERSIONS:
        raise SystemOpError(f"Unsupported Node.js version: {version!r}")
    if not node_manager_installed():
        raise SystemOpError("Node Version Manager isn't installed — install it from the App Store first.")
    _run(["n", version], timeout=180)
    # Every pm2-managed Node site runs against whatever binary "node" resolved
    # to at process start — pm2's own daemon must restart to pick up a
    # system-wide version switch, otherwise it keeps running the old binary.
    subprocess.run(["pm2", "update"], capture_output=True, timeout=30)


# ---- PHP Code Security ------------------------------------------------
# aaPanel-style hardening: disables a fixed, well-known set of dangerous PHP
# functions (arbitrary command execution, raw socket/process control) at the
# php.ini level for a given PHP-FPM version, server-wide for every site
# running that version. Off by default; the admin turns it on per PHP
# version once they're confident nothing legitimate on their sites needs
# these functions.
DANGEROUS_PHP_FUNCTIONS = [
    "exec", "shell_exec", "system", "passthru", "popen", "proc_open",
    "proc_close", "proc_get_status", "pcntl_exec", "putenv", "chroot",
    "symlink", "dl", "escapeshellarg", "escapeshellcmd",
]


def _php_security_ini_path(php_version: str) -> Path:
    if php_version not in ALLOWED_PHP_VERSIONS:
        raise SystemOpError(f"Unsupported PHP version: {php_version!r}")
    return Path(f"/etc/php/{php_version}/fpm/conf.d/99-dearsoft-security.ini")


def get_php_security_status(php_version: str) -> bool:
    path = _php_security_ini_path(php_version)
    return path.is_file() and "disable_functions" in path.read_text(encoding="utf-8")


def set_php_security_enabled(php_version: str, enabled: bool) -> None:
    path = _php_security_ini_path(php_version)
    if enabled:
        path.write_text(f"disable_functions = {','.join(DANGEROUS_PHP_FUNCTIONS)}\n", encoding="utf-8")
    elif path.is_file():
        path.unlink()
    _run(["systemctl", "restart", f"php{php_version}-fpm"], timeout=30)


# ---- Website Tamper-proof ----------------------------------------------
# Locks a site's files against modification using the ext4/xfs immutable
# attribute (chattr +i) applied recursively — even the owning process
# (PHP-FPM as www-data, or this panel running as root) can't write to a
# protected file until it's unlocked again. This is the same mechanism
# aaPanel's own tamper-proof feature is built on. Deliberately excludes
# common writable-by-design paths (uploads/cache/storage/logs) so a
# protected site doesn't break its own normal operation.
TAMPER_PROOF_EXCLUDE_DIRNAMES = {"uploads", "cache", "logs", "storage", "tmp", "temp", ".well-known"}

# Directories get locked too (not just the files already inside them) —
# otherwise locking every existing file still leaves the directory itself
# writable, so a new file (e.g. a planted backdoor .php) can simply be
# created there; existing-file immutability alone doesn't stop that. "image"
# is excluded here (unlike the file-level exclusion set above) because a
# store legitimately needs to keep uploading new product photos — locking
# existing image files already prevents someone overwriting/replacing them
# in place, which is the part worth protecting.
TAMPER_PROOF_EXCLUDE_DIRNAMES_FOR_DIRS = TAMPER_PROOF_EXCLUDE_DIRNAMES | {"image"}


def is_tamper_proof_enabled(document_root: Path) -> bool:
    marker = document_root / ".dearsoft-tamper-proof"
    return marker.is_file()


def _is_scss_compiled_output(item: Path) -> bool:
    """True for a .css file with a same-named .scss sibling — OpenCart 4.x's
    admin/controller/startup/sass.php (and its catalog-side equivalent)
    recompiles every such file from its .scss source on effectively every
    page load (only skipped if the store-specific "developer_sass" setting
    is on, which it normally isn't). Locking these breaks the whole admin
    panel with a fatal fopen()/flock() error — confirmed by hitting exactly
    this in production on a real site. Detected generically by sibling
    filename rather than hardcoding "bootstrap.css"/"stylesheet.css" so it
    holds for any theme's own compiled stylesheets too.
    """
    return item.suffix == ".css" and item.with_suffix(".scss").is_file()


def set_tamper_proof_enabled(document_root: Path, enabled: bool) -> None:
    flag = "+i" if enabled else "-i"

    # Files first (locking), directories last — a directory's own immutable
    # flag has no bearing on changing flags of files already inside it, but
    # doing files-then-dirs on enable and dirs-then-files on disable keeps
    # the two operations symmetric and easy to reason about.
    all_items = sorted(document_root.rglob("*"), key=lambda p: (p.is_dir(), -len(p.parts) if not enabled else len(p.parts)))
    for item in all_items:
        rel_parts = item.relative_to(document_root).parts[:-1] if item.is_file() else item.relative_to(document_root).parts
        if item.is_dir():
            if any(part in TAMPER_PROOF_EXCLUDE_DIRNAMES_FOR_DIRS for part in rel_parts):
                continue
            # A directory holding .scss sources needs to stay writable too,
            # in case a theme update adds a new stylesheet that hasn't been
            # compiled yet — sass.php's fopen() must be able to create it.
            if any(child.suffix == ".scss" for child in item.glob("*.scss")):
                continue
        else:
            if any(part in TAMPER_PROOF_EXCLUDE_DIRNAMES for part in rel_parts):
                continue
            if _is_scss_compiled_output(item):
                continue
        subprocess.run(["chattr", flag, str(item)], capture_output=True)

    marker = document_root / ".dearsoft-tamper-proof"
    if enabled:
        marker.write_text("Managed by DS Panel — do not delete manually while tamper-proofing is on.\n", encoding="utf-8")
        subprocess.run(["chattr", "+i", str(marker)], capture_output=True)
    elif marker.is_file():
        subprocess.run(["chattr", "-i", str(marker)], capture_output=True)
        marker.unlink()


# ---- Disk Mount Manager (read-only listing + mount/unmount only) -------
# Deliberately does NOT touch /etc/fstab — a malformed fstab entry can leave
# a server unable to boot, so v1 only lists disks/partitions and can
# mount/unmount an already-partitioned, already-filesystem'd block device on
# demand. Mounts made this way don't survive a reboot; that's the explicit
# trade-off for never being able to break one.
DISK_MOUNT_ROOT = Path("/mnt/dearsoft")
DEVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9]+$")


def list_block_devices() -> list[dict]:
    result = subprocess.run(
        ["lsblk", "-J", "-o", "NAME,SIZE,FSTYPE,MOUNTPOINT,TYPE"],
        capture_output=True, text=True, timeout=15,
    )
    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return []

    devices = []
    for dev in data.get("blockdevices", []):
        for child in dev.get("children", [dev]) if dev.get("type") == "disk" else [dev]:
            if child.get("type") not in ("part", "disk"):
                continue
            devices.append({
                "name": child.get("name"),
                "size": child.get("size"),
                "fstype": child.get("fstype"),
                "mountpoint": child.get("mountpoint"),
            })
    return devices


def mount_device(device_name: str) -> Path:
    if not DEVICE_NAME_RE.match(device_name):
        raise SystemOpError(f"Invalid device name: {device_name!r}")
    device_path = Path("/dev") / device_name
    if not device_path.exists():
        raise SystemOpError(f"No such device: {device_path}")

    mount_point = DISK_MOUNT_ROOT / device_name
    mount_point.mkdir(parents=True, exist_ok=True)
    _run(["mount", str(device_path), str(mount_point)], timeout=30)
    return mount_point


def unmount_device(device_name: str) -> None:
    if not DEVICE_NAME_RE.match(device_name):
        raise SystemOpError(f"Invalid device name: {device_name!r}")
    mount_point = DISK_MOUNT_ROOT / device_name
    _run(["umount", str(mount_point)], timeout=30)


# ---- Custom domain for the panel itself (reverse proxy) -----------------
# Lets the admin reach DS Panel's login through a real domain instead of
# https://<ip>:<port>/ — nginx terminates TLS for the domain (a real Let's
# Encrypt cert, unlike the panel's own self-signed one) and reverse-proxies
# to the panel's existing HTTPS listener on 127.0.0.1. The panel's random
# security-entrance path still applies on top of this; the domain is just a
# friendlier way to reach the same login, not a way around it.
PANEL_PROXY_VHOST_TEMPLATE = """server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    client_max_body_size 1024m;

    location / {{
        proxy_pass https://127.0.0.1:{panel_port};
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""


def set_panel_domain(domain: str, panel_port: int) -> Path:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")

    config_path = NGINX_AVAILABLE / f"ds-panel-{domain}.conf"
    config_path.write_text(
        PANEL_PROXY_VHOST_TEMPLATE.format(domain=domain, panel_port=panel_port),
        encoding="utf-8",
    )
    enabled_link = NGINX_ENABLED / f"ds-panel-{domain}.conf"
    if not enabled_link.exists():
        enabled_link.symlink_to(config_path)

    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])
    return config_path


def remove_panel_domain(domain: str) -> None:
    if not is_valid_domain(domain):
        raise SystemOpError(f"Invalid domain: {domain!r}")
    # "dearsoft-panel-" is the pre-rename prefix — vhosts created before the
    # rename still use it.
    for prefix in ("ds-panel", "dearsoft-panel"):
        (NGINX_ENABLED / f"{prefix}-{domain}.conf").unlink(missing_ok=True)
        (NGINX_AVAILABLE / f"{prefix}-{domain}.conf").unlink(missing_ok=True)
    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])
