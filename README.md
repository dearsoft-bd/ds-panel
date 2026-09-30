# DS Panel

**A free, open-source gift to server builders everywhere.**

A free, self-hosted Linux server control panel (aaPanel/cPanel-style),
installed directly on the server it manages. No license fees, no locked
features, no per-site limits — built and released by DearSoft for anyone
who runs their own servers and doesn't want to pay for the privilege of
managing them.

> A note from the founder: DS-Panel is free because I believe every
> server owner should be able to run their own infrastructure without
> paying rent for basic control-panel features. If it's useful to you,
> that's the only thank-you I need — but a star on this repo genuinely
> helps others find it.
> — Khandaker Readul Islam, Founder, DearSoft

**Status: V1 complete.** Every item below is built, deployed, and
live-verified on a real server.

## V1 — what's actually in the box

**Core**
- Install script (`install.sh`) — one command on a fresh Ubuntu/Debian box.
- Login: bcrypt password hashing, CSRF protection, per-IP brute-force
  lockout (5 attempts / 15 min), random per-install security-entrance URL
  path (nothing meaningful is reachable at a guessable `/login` or
  `/admin`), self-signed TLS from first boot.
- Google OAuth login (optional, single whitelisted account) — configurable
  entirely from **Settings**, no manual JSON editing required.
- Multi-user accounts (**Account** page, Super-Admin-only): add users with
  name/email/username/password, four roles — `super_admin` (full access,
  including user management; there's always exactly one at minimum),
  `admin` (full access except user management, unless a Super Admin
  restricts it to specific sites — then it's locked to just those sites'
  Website + File Manager pages), `viewer` (read-only, enforced globally,
  not per-route), and `custom` (sees and can use only the explicitly
  checked feature areas for that account — everything else isn't just
  read-only, it's unreachable).
- Dashboard + **Monitor**: live load/memory/disk gauges, uptime, per-service
  status (nginx/MariaDB/cron/PHP-FPM/panel itself), top processes by CPU.

**Website**
- PHP sites (versions 7.2 / 8.1 / 8.2, selectable per site, via
  `ppa:ondrej/php`) and **Node.js** sites (pm2-managed, auto-restarts,
  survives panel restarts).
- Let's Encrypt SSL via certbot, with a retry button if issuance fails the
  first time (e.g. DNS not propagated yet).
- **Domains**: point additional domain aliases at an existing site
  (nginx's native multi-name `server_name`); SSL auto-expands to cover new
  aliases if the site already has a certificate.
- Branded "Under Construction" placeholder page for brand-new sites.

**Files**
- Path-traversal-safe browser file manager: upload, edit (CodeMirror, wide
  language support incl. `.env`/`.htaccess`/`.ini`), view (images inline),
  download, rename, chmod, new file/folder, delete, bulk-delete.
- Zip/unzip with "zip slip" protection and resilient per-file extraction
  (one bad/garbled filename in an archive no longer kills the whole
  extraction); unzipped archives move to a hidden, recoverable
  `.unzipped-archives/` folder rather than being deleted.
- Copy/Cut/Paste, Select All, right-click context menu, Back/Forward/
  Reload, per-user Show Hidden Files + default-directory setting.

**Databases**
- Create/edit/delete MySQL/MariaDB databases and users; reuse an existing
  user across multiple databases (shared password, tracked correctly so
  deleting one database never revokes access to another).
- Standalone user creation (provision a user before any database exists).
- Real upstream phpMyAdmin, single-sign-on (no second login) via a
  dedicated admin-level DB account, self-signed TLS on its own port.

**Backups**
- On-demand backup button per site/database.
- Scheduled **Auto Backup**: enable per-site/database with a retention
  count, one daily cron job (02:30) backs up everything enabled and
  rotates old copies.
- **Backups** page: browse every backup by date, Download / Restore /
  Delete, with a full action log (like a lighter version of cPanel's
  AutoBackup UI).

**Operations**
- **App Store**: one-click WordPress and OpenCart (3.0.5.0 / 4.0.2.3)
  installs — downloads the real upstream release, extracts it, provisions
  a database, runs Composer where needed (OpenCart 4.x).
- **Firewall**: ufw wrapper (allow/deny by port).
- **Cron**: thin UI over the real crontab.
- **Logs**: read-only tail of nginx/PHP-FPM/MariaDB/panel logs, fixed
  allow-listed sources only, with a plain-text filter box.
- **SSH Access**: add/view/revoke public keys per system user directly
  from the panel (never touches `sshd_config` itself — only
  `authorized_keys` — so a mistake here is always recoverable).
- **Terminal**: off by default, explicit toggle required, WebSocket-to-PTY
  bridge, Origin-header checked.

**Security architecture** (see `app/system_ops.py`'s module docstring —
this is the single most important file in the codebase):
1. Every privileged OS operation goes through `system_ops.py` only.
2. `subprocess` calls always use an argument **list**, never
   `shell=True` with interpolated strings.
3. Every filename/domain/identifier is validated against a strict
   allow-list regex as defense in depth on top of rule 2.
4. Every File Manager (and site-creation) write hands file ownership back
   to `www-data` immediately — the panel itself runs as `root` for its
   other privileged duties, so anything it creates would otherwise be
   unreadable/unwritable by PHP-FPM.

## V2 roadmap (not built yet)

Requested:
- **Theme/color customization** — let the admin pick an accent color or
  swap the orange/yellow scheme, instead of it being hardcoded in
  `style.css`.
- **Custom shortcut menu** — admin-configurable quick-launch bar/favorites
  for the sidebar.
- **LiteSpeed Cache** — install/manage LSCache (or an OpenLiteSpeed
  migration path) for sites that want it.
- **AI Web Builder** — AI-assisted page/theme generation for a new site.
- **AI Chat Widget** — droppable AI chatbot snippet for a site's storefront.
- **AI Background Remover (free tier)** — local/free image background
  removal tool, bundled with the panel.

Suggested additions (not requested, but natural next steps given what's
already built):
- **Historical resource monitoring** — a periodic sampler + small
  time-series table so Monitor can show trend graphs, not just a live
  snapshot (flagged during v1, deliberately deferred).
- **Two-factor login (TOTP)** — meaningful hardening now that multi-user
  accounts exist.
- **Docker** — basic container list/start/stop/logs (currently a disabled
  sidebar placeholder).
- **Full WAF** — the current Firewall is a ufw port wrapper by design;
  a real request-inspecting WAF (ModSecurity-class) is a separate,
  larger project.
- **Mail Server** — deferred this session specifically because GCP blocks
  outbound port 25 by default; revisit once that's not a blocker (either
  a non-GCP box, or after requesting the unblock from Google).
- **Laravel one-click install** — deferred in v1 because it needs a live
  `composer create-project` run (heavier/more fragile than "download a
  release zip"); now that Composer is already installed (for OpenCart
  4.x), this is more feasible.
- **Site staging/cloning** — duplicate an existing site (files + DB) to a
  staging domain in one click.
- **Git-based deploys** — pull from a repo on push/webhook instead of
  File Manager uploads.
- **Offsite backup targets** — ship scheduled backups to S3-compatible
  storage, not just local disk.
- **API tokens** — programmatic access to the panel (create a site,
  trigger a backup, etc.) without going through the browser.

## Google OAuth login (optional)

Configurable entirely from the **Settings** page in the panel UI now — no
manual file editing needed. In short: create an OAuth client in
[Google Cloud Console](https://console.cloud.google.com/apis/credentials)
(type: Web application), paste the panel's pre-filled Redirect URI into
its Authorized redirect URIs, then paste the Client ID/Secret and your
allowed email back into Settings → Google OAuth Login → Save, and run
`sudo systemctl restart ds-panel` to apply it.

## Install (production)

On a fresh Ubuntu/Debian server, as root:

```bash
sudo bash install.sh
```

The installer prints your login URL, username, and a generated password
**once** — save it immediately, it is never stored in plaintext and cannot
be recovered later (only reset by re-running the generator against a fresh
config).

Re-running `install.sh` on an already-installed server is safe and
idempotent — it's how every update in this project gets deployed
(syncs code, runs DB migrations, restarts the service).

## Local development

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python scripts/generate_config.py --config-dir instance
DS_PANEL_CONFIG=instance/config.json venv/bin/python run.py
```

Then open `https://127.0.0.1:<port>/<security-path>/login` using the URL
printed by `generate_config.py` (your browser will warn about the
self-signed cert — that's expected in dev).

## Cloud firewall (GCP/AWS/etc.)

`install.sh` opens the panel's port locally (ufw), but cloud providers also
enforce their own network-level firewall in front of the VM — **every**
port this panel uses (the panel itself, phpMyAdmin, and 80/443 for every
hosted site) needs an explicit inbound rule there too, or it's unreachable
from outside regardless of what ufw says. On GCP: **VPC network →
Firewall → Create Firewall Rule**, source `0.0.0.0/0`, protocol TCP, the
specific port(s) — don't use a broad "allow all" rule; open only what's
actually running. Equivalent step needed on AWS (Security Group) / other
clouds.

If the target VM has **OS Login enabled** (common on GCP), the instance's
"SSH Keys" metadata field is silently ignored — the guest agent only
manages `~/.ssh/authorized_keys` from OS Login / ephemeral browser-SSH
keys, and will overwrite any key added there, including ones added via
the panel's own **SSH Access** page. Fix: instance **Edit → Custom
metadata → add `enable-oslogin` = `FALSE`**, *then* manage keys normally
(via the panel's SSH Access page, or the SSH Keys metadata field).

## Security design notes

- Every privileged OS operation (file writes outside the panel's own
  storage, nginx config, certbot, crontab, ufw, MySQL) must go through an
  explicit, allow-listed helper function in `app/system_ops.py` using
  `subprocess` with an **argument list** — never `shell=True` with
  interpolated strings. This is the single rule most responsible for this
  class of software staying safe.
- Login lives under a random per-install URL path, not a guessable
  `/login` or `/admin` — see `app/config.py`'s `security_path`.
- The web terminal is off by default and must be explicitly enabled by an
  authenticated admin before it's reachable at all.
- The `viewer` role is enforced once, globally (`app/__init__.py`'s
  `before_request` hook blocks every non-GET request for that role) —
  not re-implemented per route, so it can't be silently bypassed by a
  route that forgot to check.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, run it on as many servers
as you want, free of charge.
