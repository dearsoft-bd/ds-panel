"""Loads the panel's runtime config, generated once at install time by
scripts/generate_config.py (random port, random security-entrance path,
secret key, SSL cert paths). Never hand-edited in normal operation.
"""
import json
import os
from pathlib import Path


class ConfigError(RuntimeError):
    pass


class Config:
    def __init__(self, data: dict, config_path: Path):
        self.secret_key: str = data["secret_key"]
        self.security_path: str = data["security_path"]
        self.port: int = data["port"]
        self.host: str = data.get("host", "0.0.0.0")
        self.ssl_cert: str = data["ssl_cert"]
        self.ssl_key: str = data["ssl_key"]
        self.db_path: Path = Path(data["db_path"])
        self.config_path = config_path
        self.pma_port: int | None = data.get("pma_port")

        # Optional — Google OAuth login. Unset until the admin fills these
        # in (see README). google_allowed_email is a single whitelisted
        # address: this panel controls a real server, so OAuth login is
        # deliberately NOT open registration for any Google account, only
        # the one address the admin explicitly configures.
        oauth = data.get("oauth", {})
        self.google_client_id: str = oauth.get("google_client_id", "")
        self.google_client_secret: str = oauth.get("google_client_secret", "")
        self.google_allowed_email: str = oauth.get("google_allowed_email", "").strip().lower()
        self.google_redirect_uri: str = oauth.get("google_redirect_uri", "")

        # Optional — AI Assistant. "claude" or "openai"; unset until the
        # admin configures a provider + their own API key in Settings. If
        # left unset, AI Assistant still works out of the box via
        # DearSoft's free relay (see ai_engine.py's _call_relay) — a
        # 7-day trial per install, identified only by install_id below.
        ai = data.get("ai", {})
        self.ai_provider: str = ai.get("provider", "")
        self.ai_api_key: str = ai.get("api_key", "")
        self.ai_model: str = ai.get("model", "")

        # Random per-install identifier, generated once at install time
        # (or lazily on first load for pre-existing installs — see
        # load_config()). Used only to track the free AI relay trial
        # window/quota; carries no other identifying information.
        self.install_id: str = data.get("install_id", "")

        # Optional — a friendly domain that reverse-proxies to this panel
        # (see system_ops.set_panel_domain), so login doesn't require
        # remembering the raw <ip>:<port>. The random security-entrance path
        # still applies on top of whichever URL reaches the panel.
        self.panel_domain: str = data.get("panel_domain", "")

        # Optional — outbound SMTP for "Forgot Password" reset emails only
        # (not a general mailer). Deliberately a configurable external relay
        # (Gmail/SendGrid/Namecheap SMTP/etc.), not the panel's own bundled
        # Postfix — this needs to reach the admin's real inbox reliably even
        # on hosts like GCP that block outbound port 25 for the panel's own
        # mail server, so 587/TLS to a relay the admin already trusts is the
        # dependable choice for a security-critical email.
        smtp = data.get("smtp", {})
        self.smtp_host: str = smtp.get("host", "")
        self.smtp_port: int = int(smtp.get("port", 587) or 587)
        self.smtp_username: str = smtp.get("username", "")
        self.smtp_password: str = smtp.get("password", "")
        self.smtp_from_address: str = smtp.get("from_address", "")
        self.smtp_use_tls: bool = smtp.get("use_tls", True)

    @property
    def smtp_enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_from_address)

    @property
    def google_oauth_enabled(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret and self.google_allowed_email)

    @property
    def ai_enabled(self) -> bool:
        # Always true — either the admin's own key (if configured) or the
        # free DearSoft relay trial. Errors from the relay (trial expired,
        # daily cap hit) surface as a chat message, not a disabled page.
        return True

    @property
    def login_url(self) -> str:
        return f"/{self.security_path}/login"

    @property
    def dashboard_url(self) -> str:
        return f"/{self.security_path}/"


def default_config_path() -> Path:
    # Overridable via env var so the app can run from a non-standard
    # location during development (see instance/config.json in this repo).
    # DEARSOFT_PANEL_CONFIG is the pre-rename name, still honoured so an
    # older unit file keeps working until install.sh rewrites it.
    env_path = os.environ.get("DS_PANEL_CONFIG") or os.environ.get("DEARSOFT_PANEL_CONFIG")
    if env_path:
        return Path(env_path)
    return Path("/etc/ds-panel/config.json")


def load_config(config_path: Path | None = None) -> Config:
    path = config_path or default_config_path()
    if not path.is_file():
        raise ConfigError(
            f"No config found at {path}. Run install.sh (or "
            "scripts/generate_config.py for local development) first."
        )
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Installs created before install_id existed don't have one yet —
    # generate it once here and persist it back, so it's stable across
    # restarts instead of being regenerated (and losing trial history)
    # every time the app boots.
    if not data.get("install_id"):
        import secrets
        data["install_id"] = secrets.token_hex(16)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    return Config(data, path)
