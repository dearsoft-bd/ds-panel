"""AI Assistant — a chat interface backed by either Claude or OpenAI (the
admin's own API key, configured in Settings), with a small, explicit,
allow-listed set of tools it may call. Read-only tools (status/listings)
execute automatically; anything that changes server state (restart a
service, trigger a backup) stops and waits for the admin to click Confirm
in the UI before it actually runs — same "the AI never gets to skip the
human" boundary as everything else privileged in this codebase goes
through system_ops.py's allow-listed functions rather than a raw shell.
"""
import json
import re
import secrets
import string

import requests

from . import system_ops

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Free-tier fallback used whenever the admin hasn't configured their own
# provider + key in Settings — see _call_relay(). Holds DearSoft's own
# OpenAI key server-side only; never shipped in panel code or the compiled
# binary. 7-day trial + daily cap enforced there, keyed by install_id.
RELAY_URL = "https://license.dearsoft.com.bd/api/ai-relay.php"

SYSTEM_PROMPT = (
    "You are the AI Assistant built into DS Panel, a self-hosted Linux server "
    "control panel. Use the available tools when they help answer a question "
    "or carry out a request — don't guess at server state you can look up. "
    "Keep answers short and practical. Actions that change anything on the "
    "server require the admin to confirm in the UI before they run; you'll "
    "be told the outcome once they do."
)

# Tools the AI may call. "confirm": True means the UI stops and shows a
# Confirm/Cancel prompt before execute_tool() ever runs — the LLM's own
# decision to call the tool is never enough on its own for anything that
# changes server state.
TOOLS = [
    {
        "name": "get_server_status",
        "description": "Get current server status: CPU load, memory usage, disk usage, uptime.",
        "schema": {"type": "object", "properties": {}},
        "confirm": False,
    },
    {
        "name": "list_sites",
        "description": "List websites managed by DS Panel (domain, type, SSL status).",
        "schema": {"type": "object", "properties": {}},
        "confirm": False,
    },
    {
        "name": "list_databases",
        "description": "List MySQL databases managed by DS Panel.",
        "schema": {"type": "object", "properties": {}},
        "confirm": False,
    },
    {
        "name": "list_services",
        "description": "List monitored system services (nginx, MariaDB, cron, PHP-FPM) and whether each is running.",
        "schema": {"type": "object", "properties": {}},
        "confirm": False,
    },
    {
        "name": "restart_service",
        "description": "Restart a system service. unit must be one of the exact names returned by list_services, e.g. 'nginx'.",
        "schema": {"type": "object", "properties": {"unit": {"type": "string"}}, "required": ["unit"]},
        "confirm": True,
    },
    {
        "name": "backup_site",
        "description": "Create a backup of a website's files right now. domain must be one of the domains returned by list_sites.",
        "schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
        "confirm": True,
    },
    {
        "name": "backup_database",
        "description": "Create a backup (SQL dump) of a MySQL database right now. db_name must be one of the names returned by list_databases.",
        "schema": {"type": "object", "properties": {"db_name": {"type": "string"}}, "required": ["db_name"]},
        "confirm": True,
    },
    {
        "name": "create_site",
        "description": (
            "Create a new website (nginx vhost + document root). domain is required. "
            "site_type is 'php' (default) or 'node'. php_version defaults to the panel's default "
            "if omitted. Set want_ssl true + a valid admin_email to also issue a Let's Encrypt "
            "certificate (the domain's DNS must already point at this server for that to succeed)."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "site_type": {"type": "string", "enum": ["php", "node"]},
                "php_version": {"type": "string"},
                "want_ssl": {"type": "boolean"},
                "admin_email": {"type": "string"},
            },
            "required": ["domain"],
        },
        "confirm": True,
    },
    {
        "name": "create_database",
        "description": (
            "Create a new MySQL database and a dedicated user for it. db_name and db_user must be "
            "letters/digits/underscores only, starting with a letter. A random password is generated "
            "and returned in the result — show it to the admin, it is never stored in plaintext."
        ),
        "schema": {
            "type": "object",
            "properties": {"db_name": {"type": "string"}, "db_user": {"type": "string"}},
            "required": ["db_name", "db_user"],
        },
        "confirm": True,
    },
    {
        "name": "add_cron_job",
        "description": "Add a cron job to root's crontab. schedule is standard 5-field cron syntax (e.g. '0 3 * * *'), command is the shell command to run.",
        "schema": {
            "type": "object",
            "properties": {"schedule": {"type": "string"}, "command": {"type": "string"}},
            "required": ["schedule", "command"],
        },
        "confirm": True,
    },
    {
        "name": "allow_firewall_port",
        "description": "Open a port through the firewall (ufw allow).",
        "schema": {"type": "object", "properties": {"port": {"type": "integer"}}, "required": ["port"]},
        "confirm": True,
    },
    {
        "name": "deny_firewall_port",
        "description": "Close a previously-opened firewall port (ufw deny). SSH (22) and the panel's own port can never be closed this way.",
        "schema": {"type": "object", "properties": {"port": {"type": "integer"}}, "required": ["port"]},
        "confirm": True,
    },
]

# Mirrors firewall.py's PROTECTED_PORTS — SSH is never closeable via any
# path, including the AI, to rule out an unrecoverable self-lockout.
FIREWALL_PROTECTED_PORTS = {22}


def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))
CONFIRM_TOOLS = {t["name"] for t in TOOLS if t["confirm"]}
TOOL_MAX_ROUNDS = 6  # safety cap so a confused model can't loop forever


class AIError(RuntimeError):
    pass


def execute_tool(cfg, db, name: str, args: dict) -> dict:
    if name == "get_server_status":
        stats = system_ops.get_system_stats()
        stats["uptime"] = system_ops.get_uptime()
        return stats
    if name == "list_sites":
        rows = db.execute("SELECT domain, site_type, ssl_enabled FROM sites ORDER BY domain").fetchall()
        return {"sites": [dict(r) for r in rows]}
    if name == "list_databases":
        rows = db.execute("SELECT db_name, db_user FROM databases ORDER BY db_name").fetchall()
        return {"databases": [dict(r) for r in rows]}
    if name == "list_services":
        return {"services": system_ops.monitored_services()}
    if name == "restart_service":
        system_ops.restart_service(args.get("unit", ""))
        return {"ok": True, "restarted": args.get("unit", "")}
    if name == "backup_site":
        path = system_ops.backup_site(args.get("domain", ""))
        return {"ok": True, "backup_file": path.name}
    if name == "backup_database":
        path = system_ops.backup_database(args.get("db_name", ""))
        return {"ok": True, "backup_file": path.name}

    if name == "create_site":
        domain = (args.get("domain") or "").strip().lower()
        site_type = args.get("site_type") or "php"
        php_version = args.get("php_version") or system_ops.DEFAULT_PHP_VERSION
        want_ssl = bool(args.get("want_ssl"))
        admin_email = (args.get("admin_email") or "").strip()

        if not system_ops.is_valid_domain(domain):
            raise AIError(f"{domain!r} doesn't look like a valid domain.")
        if site_type not in ("php", "node"):
            raise AIError("site_type must be 'php' or 'node'.")
        if site_type == "php" and php_version not in system_ops.ALLOWED_PHP_VERSIONS:
            raise AIError(f"Invalid PHP version {php_version!r}.")
        if db.execute("SELECT id FROM sites WHERE domain = ?", (domain,)).fetchone():
            raise AIError(f"{domain} already exists.")
        if want_ssl and not EMAIL_RE.match(admin_email):
            raise AIError("A valid admin_email is required to issue an SSL certificate.")

        node_port = None
        document_root = system_ops.create_site_directory(domain)
        if site_type == "node":
            existing_ports = [
                row["node_port"]
                for row in db.execute("SELECT node_port FROM sites WHERE node_port IS NOT NULL").fetchall()
            ]
            node_port = system_ops.allocate_node_port(existing_ports)
            system_ops.scaffold_node_app(domain, document_root, node_port)
            system_ops.write_node_nginx_vhost(domain, node_port)
            system_ops.start_node_app(domain, document_root, node_port)
        else:
            system_ops.write_nginx_vhost(domain, php_version)

        ssl_enabled, ssl_error = False, None
        if want_ssl:
            try:
                system_ops.issue_certificate(domain, admin_email)
                ssl_enabled = True
            except system_ops.SystemOpError as e:
                ssl_error = str(e)

        db.execute(
            "INSERT INTO sites (domain, document_root, ssl_enabled, php_version, site_type, node_port) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (domain, str(document_root), 1 if ssl_enabled else 0, php_version, site_type, node_port),
        )
        db.commit()
        result = {"ok": True, "domain": domain, "ssl_enabled": ssl_enabled}
        if ssl_error:
            result["ssl_error"] = ssl_error
        return result

    if name == "create_database":
        db_name = (args.get("db_name") or "").strip()
        db_user = (args.get("db_user") or "").strip()
        if not system_ops.is_valid_db_identifier(db_name):
            raise AIError("db_name must start with a letter and contain only letters, digits, underscores.")
        if not system_ops.is_valid_db_identifier(db_user):
            raise AIError("db_user must start with a letter and contain only letters, digits, underscores.")
        if db.execute("SELECT id FROM databases WHERE db_name = ?", (db_name,)).fetchone():
            raise AIError(f"Database '{db_name}' already exists.")
        known_users = (
            {row["db_user"] for row in db.execute("SELECT DISTINCT db_user FROM databases").fetchall()}
            | {row["username"] for row in db.execute("SELECT username FROM db_users").fetchall()}
        )
        if db_user in known_users:
            raise AIError(f"User '{db_user}' already exists — pick a different db_user.")

        password = _random_password()
        system_ops.create_database(db_name, db_user, password)
        db.execute("INSERT INTO databases (db_name, db_user) VALUES (?, ?)", (db_name, db_user))
        db.commit()
        return {"ok": True, "db_name": db_name, "db_user": db_user, "password": password}

    if name == "add_cron_job":
        schedule = (args.get("schedule") or "").strip()
        command = (args.get("command") or "").strip()
        if not schedule or not command:
            raise AIError("Both schedule and command are required.")
        system_ops.add_cron_job(schedule, command)
        return {"ok": True, "schedule": schedule, "command": command}

    if name in ("allow_firewall_port", "deny_firewall_port"):
        try:
            port = int(args.get("port"))
        except (TypeError, ValueError):
            raise AIError("port must be an integer.")
        if not (1 <= port <= 65535):
            raise AIError("port must be between 1 and 65535.")
        if name == "deny_firewall_port" and (port in FIREWALL_PROTECTED_PORTS or port == cfg.port):
            raise AIError(f"Port {port} is protected (SSH or the panel itself) and can't be closed here.")
        (system_ops.allow_port if name == "allow_firewall_port" else system_ops.deny_port)(port)
        return {"ok": True, "port": port, "action": "allow" if name == "allow_firewall_port" else "deny"}

    raise AIError(f"Unknown tool {name!r}")


def _claude_tools():
    return [{"name": t["name"], "description": t["description"], "input_schema": t["schema"]} for t in TOOLS]


def _openai_tools():
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["schema"]}} for t in TOOLS]


def _call_claude(cfg, raw_messages: list) -> dict:
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": cfg.ai_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": cfg.ai_model or "claude-sonnet-4-5",
                "max_tokens": 1024,
                "system": SYSTEM_PROMPT,
                "messages": raw_messages,
                "tools": _claude_tools(),
            },
            timeout=60,
        )
    except requests.RequestException as e:
        raise AIError(f"Couldn't reach Claude's API: {e}") from e
    if resp.status_code != 200:
        raise AIError(f"Claude API error ({resp.status_code}): {resp.text[:300]}")
    return resp.json()


def _call_openai(cfg, raw_messages: list) -> dict:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + raw_messages
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {cfg.ai_api_key}", "Content-Type": "application/json"},
            json={"model": cfg.ai_model or "gpt-4o-mini", "messages": messages, "tools": _openai_tools()},
            timeout=60,
        )
    except requests.RequestException as e:
        raise AIError(f"Couldn't reach OpenAI's API: {e}") from e
    if resp.status_code != 200:
        raise AIError(f"OpenAI API error ({resp.status_code}): {resp.text[:300]}")
    return resp.json()


def _call_relay(cfg, raw_messages: list) -> dict:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + raw_messages
    try:
        resp = requests.post(
            RELAY_URL,
            json={"caller": "ds_panel", "install_id": cfg.install_id, "messages": messages, "tools": _openai_tools()},
            timeout=60,
        )
    except requests.RequestException as e:
        raise AIError(f"Couldn't reach DearSoft's free AI service: {e}") from e

    try:
        data = resp.json()
    except ValueError:
        data = {}

    if resp.status_code == 402:
        raise AIError(data.get("message") or "DS Panel's free 7-day AI trial has ended. Add your own API key in Settings to keep using AI Assistant.")
    if resp.status_code == 429:
        raise AIError(data.get("message") or "Free AI usage limit reached for today — try again tomorrow, or add your own API key in Settings.")
    if resp.status_code != 200:
        raise AIError(f"DearSoft AI relay error ({resp.status_code}): {resp.text[:300]}")
    return data


def _append_tool_result(cfg, raw_messages: list, tool_name: str, tool_id: str, result: dict) -> None:
    if cfg.ai_provider == "claude":
        raw_messages.append({
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": json.dumps(result)}],
        })
    else:
        raw_messages.append({"role": "tool", "tool_call_id": tool_id, "content": json.dumps(result)})


def _one_llm_step(cfg, raw_messages: list, display_messages: list):
    """Calls the LLM once, records what it said/asked for, and returns
    either ('done', None) or ('tool_call', {name, args, id}).
    """
    if cfg.ai_provider == "claude" and cfg.ai_api_key:
        data = _call_claude(cfg, raw_messages)
        content_blocks = data.get("content", [])
        raw_messages.append({"role": "assistant", "content": content_blocks})
        text_parts = [b["text"] for b in content_blocks if b.get("type") == "text" and b.get("text")]
        if text_parts:
            display_messages.append({"role": "assistant", "text": "\n".join(text_parts)})
        tool_blocks = [b for b in content_blocks if b.get("type") == "tool_use"]
        if not tool_blocks:
            return "done", None
        tool = tool_blocks[0]
        return "tool_call", {"name": tool["name"], "args": tool.get("input") or {}, "id": tool["id"]}

    # OpenAI-shaped response either way: the admin's own OpenAI key, or
    # DearSoft's free relay (which forwards OpenAI's raw response as-is).
    use_own_openai = cfg.ai_provider == "openai" and cfg.ai_api_key
    data = _call_openai(cfg, raw_messages) if use_own_openai else _call_relay(cfg, raw_messages)
    msg = data["choices"][0]["message"]
    raw_messages.append(msg)
    if msg.get("content"):
        display_messages.append({"role": "assistant", "text": msg["content"]})
    tool_calls = msg.get("tool_calls") or []
    if not tool_calls:
        return "done", None
    call = tool_calls[0]
    try:
        args = json.loads(call["function"]["arguments"] or "{}")
    except json.JSONDecodeError:
        args = {}
    return "tool_call", {"name": call["function"]["name"], "args": args, "id": call["id"]}


def run_turn(cfg, db, raw_messages: list, display_messages: list) -> dict:
    """Advances the conversation, auto-running safe tools and stopping at
    the first tool call that needs confirmation (or at a final answer).
    Mutates raw_messages/display_messages in place. Returns
    {"status": "done"} or {"status": "needs_confirm", "pending": {...}}.
    """
    for _ in range(TOOL_MAX_ROUNDS):
        kind, tool = _one_llm_step(cfg, raw_messages, display_messages)
        if kind == "done":
            return {"status": "done"}

        if tool["name"] in CONFIRM_TOOLS:
            return {"status": "needs_confirm", "pending": tool}

        try:
            result = execute_tool(cfg, db, tool["name"], tool["args"])
        except (system_ops.SystemOpError, AIError) as e:
            result = {"error": str(e)}
        _append_tool_result(cfg, raw_messages, tool["name"], tool["id"], result)
        display_messages.append({"role": "tool", "text": f"[{tool['name']}] {json.dumps(result)[:300]}"})

    display_messages.append({"role": "assistant", "text": "(Stopped after several tool calls in a row — ask me to continue if needed.)"})
    return {"status": "done"}


def resume_after_confirmation(cfg, db, raw_messages: list, display_messages: list, pending: dict, approved: bool) -> dict:
    if approved:
        try:
            result = execute_tool(cfg, db, pending["name"], pending["args"])
        except (system_ops.SystemOpError, AIError) as e:
            result = {"error": str(e)}
    else:
        result = {"declined": True, "message": "The admin declined this action."}
    _append_tool_result(cfg, raw_messages, pending["name"], pending["id"], result)
    display_messages.append({"role": "tool", "text": f"[{pending['name']}] {json.dumps(result)[:300]}"})
    return run_turn(cfg, db, raw_messages, display_messages)
