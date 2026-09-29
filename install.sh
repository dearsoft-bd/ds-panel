#!/usr/bin/env bash
# DS Panel — installer. Run as root on a fresh Ubuntu/Debian server:
#   sudo bash install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root (sudo bash install.sh)." >&2
    exit 1
fi

INSTALL_DIR="/opt/ds-panel"
CONFIG_DIR="/etc/ds-panel"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Migrate a pre-rename install (dearsoft-panel -> ds-panel): stop the old
# service and move its code/config dirs over so venv, panel.db, SSL certs
# and config.json all carry across untouched.
if [[ -f /etc/systemd/system/dearsoft-panel.service ]]; then
    echo "==> Migrating existing dearsoft-panel install to ds-panel"
    systemctl disable --now --quiet dearsoft-panel || true
    rm -f /etc/systemd/system/dearsoft-panel.service
    systemctl daemon-reload
fi
if [[ -d /opt/dearsoft-panel && ! -e "$INSTALL_DIR" ]]; then
    mv /opt/dearsoft-panel "$INSTALL_DIR"
    # A venv hardcodes its own absolute path in every script shebang, so the
    # moved one is broken — drop it and let the step below rebuild it.
    rm -rf "$INSTALL_DIR/venv"
fi
if [[ -d /etc/dearsoft-panel && ! -e "$CONFIG_DIR" ]]; then
    mv /etc/dearsoft-panel "$CONFIG_DIR"
fi
if [[ -d /var/backups/dearsoft-panel && ! -e /var/backups/ds-panel ]]; then
    mv /var/backups/dearsoft-panel /var/backups/ds-panel
fi

# Without this, apt-get still shows an interactive debconf prompt for
# certain packages (postfix chief among them) even when its answers were
# pre-seeded via debconf-set-selections — and over an SSH session with no
# real TTY, that prompt just hangs forever instead of erroring out.
export DEBIAN_FRONTEND=noninteractive

echo "==> Installing system dependencies"
apt-get update -qq
apt-get install -y -qq software-properties-common python3 python3-venv python3-pip openssl rsync \
    nginx certbot python3-certbot-nginx mariadb-server ufw cron unzip composer >/dev/null
systemctl enable --quiet --now mariadb
systemctl enable --quiet --now cron

echo "==> Installing Python 3.11 (deadsnakes PPA)"
# The panel's venv is built against 3.11 specifically. Ubuntu ships whatever
# its own release carries as "python3" (3.10 on 22.04, 3.12 on 24.04) — never
# reliably 3.11 — so this is pinned explicitly the same way PHP's multiple
# versions are pinned above, rather than trusting the distro default.
if ! command -v python3.11 >/dev/null 2>&1; then
    add-apt-repository -y ppa:deadsnakes/ppa >/dev/null 2>&1
    apt-get update -qq
    apt-get install -y -qq python3.11 python3.11-venv python3.11-dev >/dev/null
fi

echo "==> Installing PHP 7.2 (legacy), 8.1 (default), 8.2, 8.5 via ppa:ondrej/php"
# Ubuntu 24.04's own repos only ship one PHP version — this PPA is the
# standard way every PHP-based control panel gets multiple versions
# side-by-side on a modern Ubuntu base.
add-apt-repository -y ppa:ondrej/php >/dev/null 2>&1
apt-get update -qq
for PHPV in 7.2 8.1 8.2 8.5; do
    apt-get install -y -qq \
        "php${PHPV}-fpm" "php${PHPV}-mysqli" "php${PHPV}-mbstring" \
        "php${PHPV}-zip" "php${PHPV}-xml" "php${PHPV}-curl" "php${PHPV}-gd" >/dev/null
    # Stock php-fpm defaults (2M upload / 8M post) reject any real theme
    # import, product-image bulk upload, or database import long before
    # nginx's own client_max_body_size (set per-vhost) ever matters.
    if [[ -d "/etc/php/${PHPV}/fpm/conf.d" ]]; then
        cat > "/etc/php/${PHPV}/fpm/conf.d/99-dearsoft-uploads.ini" << PHPINI
upload_max_filesize = 50M
post_max_size = 50M
max_execution_time = 300
max_input_time = 300
memory_limit = 512M
PHPINI
    fi
    systemctl enable --quiet --now "php${PHPV}-fpm"
    # enable --now is a no-op on a version that was already running from a
    # prior install, so the new upload-limit ini above wouldn't actually
    # take effect without an explicit restart here.
    systemctl restart "php${PHPV}-fpm"
done

echo "==> Installing Node.js LTS + pm2 (via NodeSource — Ubuntu's own repo is too old)"
if ! command -v node >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1
    apt-get install -y -qq nodejs >/dev/null
fi
npm install -g pm2 --silent >/dev/null 2>&1
PM2_BIN=$(command -v pm2)
if [[ -n "$PM2_BIN" ]]; then
    env PATH=$PATH:/usr/bin pm2 startup systemd -u root --hp /root >/dev/null 2>&1 || true
fi

echo "==> WAF (ModSecurity) and Apache are installed on-demand from the App Store page, not bundled here — not every server wants a second web server or WAF overhead running by default."

echo "==> Installing Docker"
if ! command -v docker >/dev/null 2>&1; then
    apt-get install -y -qq docker.io docker-compose-v2 >/dev/null
fi
systemctl enable --quiet --now docker

echo "==> Installing Mail Server (Postfix + Dovecot)"
# Pre-seed debconf so postfix's installer doesn't block on an interactive
# prompt during an automated run — "Internet Site" is the standard mode
# for a self-hosted mail server; mailname is fully reconfigurable later.
debconf-set-selections <<< "postfix postfix/main_mailer_type select Internet Site"
debconf-set-selections <<< "postfix postfix/mailname string $(hostname -f)"
apt-get install -y -qq postfix dovecot-core dovecot-imapd dovecot-lmtpd >/dev/null

id -u vmail >/dev/null 2>&1 || useradd -r -u 5000 -g mail -d /var/mail/vhosts -s /usr/sbin/nologin vmail
mkdir -p /var/mail/vhosts
chown -R vmail:mail /var/mail/vhosts
chmod 770 /var/mail/vhosts

touch /etc/postfix/vhosts /etc/postfix/vmailbox /etc/postfix/valias
postmap /etc/postfix/vmailbox
postmap /etc/postfix/valias

MAIL_SSL_DIR="$CONFIG_DIR/ssl-mail"
if [[ ! -f "$MAIL_SSL_DIR/mail.crt" ]]; then
    mkdir -p "$MAIL_SSL_DIR"
    # X.509's CommonName field has a strict 64-character limit — some
    # cloud providers' auto-generated internal FQDNs (GCP among them,
    # e.g. "host.zone.c.project-id.internal") blow past that, which makes
    # openssl fail outright. This is just a self-signed placeholder cert
    # (swap in a real one per mail domain later), so a short fixed CN is
    # fine — no need for it to match the real hostname at all.
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$MAIL_SSL_DIR/mail.key" -out "$MAIL_SSL_DIR/mail.crt" \
        -days 825 -subj "/CN=ds-panel-mail" >/dev/null 2>&1
fi

postconf -e "virtual_mailbox_domains = /etc/postfix/vhosts"
postconf -e "virtual_mailbox_base = /var/mail/vhosts"
postconf -e "virtual_mailbox_maps = hash:/etc/postfix/vmailbox"
postconf -e "virtual_alias_maps = hash:/etc/postfix/valias"
postconf -e "virtual_minimum_uid = 5000"
postconf -e "virtual_uid_maps = static:5000"
postconf -e "virtual_gid_maps = static:8"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_security_options = noanonymous"
postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination"
postconf -e "smtpd_tls_cert_file = ${MAIL_SSL_DIR}/mail.crt"
postconf -e "smtpd_tls_key_file = ${MAIL_SSL_DIR}/mail.key"
postconf -e "smtpd_use_tls = yes"

# Submission (587, STARTTLS + SASL) — how real mail clients send, not raw
# port 25. Appended rather than uncommenting master.cf's own commented
# block, since that block's exact text varies by Postfix version and is
# fragile to sed; appending a fresh explicit block is idempotent and
# version-independent.
if ! grep -q "^submission" /etc/postfix/master.cf; then
    cat >> /etc/postfix/master.cf << 'MASTERCF'

submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
MASTERCF
fi

cat > /etc/dovecot/conf.d/99-dearsoft-mail.conf << DOVECOTCONF
mail_location = maildir:/var/mail/vhosts/%d/%n
namespace inbox {
  inbox = yes
}
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/dearsoft-users
}
userdb {
  driver = static
  args = uid=vmail gid=mail home=/var/mail/vhosts/%d/%n
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
ssl = yes
ssl_cert = <${MAIL_SSL_DIR}/mail.crt
ssl_key = <${MAIL_SSL_DIR}/mail.key
DOVECOTCONF

touch /etc/dovecot/dearsoft-users
chmod 640 /etc/dovecot/dearsoft-users
chown root:dovecot /etc/dovecot/dearsoft-users

systemctl enable --quiet --now postfix
systemctl enable --quiet --now dovecot
systemctl restart postfix
systemctl restart dovecot

ufw allow 25/tcp >/dev/null
ufw allow 587/tcp >/dev/null
ufw allow 993/tcp >/dev/null

mkdir -p /var/www/dearsoft-sites
# www-data needs write access to this directory itself (not just the
# per-site folders inside it) — some apps (OpenCart's installer among
# them) deliberately create a sibling "-storage"-style folder next to a
# site's own document root, outside the public webroot, for security.
# Every site here already runs as www-data with no cross-site isolation,
# so this doesn't weaken anything that wasn't already shared.
chown www-data:www-data /var/www/dearsoft-sites
chmod 775 /var/www/dearsoft-sites

echo "==> Copying application to ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"
rsync -a --exclude 'instance' --exclude '.git' --exclude '__pycache__' "$SOURCE_DIR"/ "$INSTALL_DIR"/

echo "==> Creating virtualenv (Python 3.11)"
python3.11 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

if [[ -f "$CONFIG_DIR/config.json" ]]; then
    echo "==> Existing config found at ${CONFIG_DIR}/config.json — skipping generation."
    echo "    (Delete it first if you intentionally want a fresh install.)"
else
    echo "==> Generating configuration, TLS certificate, and admin account(s)"
    # Optional: create more than one admin login on first boot, e.g.
    #   DS_EXTRA_ADMINS="mahin,sagor" sudo bash install.sh
    # Extra admins can always be added later from the Account page too —
    # this just saves creating them one at a time right after a fresh install.
    EXTRA_ADMINS_ARGS=()
    if [[ -n "${DS_EXTRA_ADMINS:-}" ]]; then
        EXTRA_ADMINS_ARGS=(--extra-admins "$DS_EXTRA_ADMINS")
    fi
    "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/scripts/generate_config.py" --config-dir "$CONFIG_DIR" "${EXTRA_ADMINS_ARGS[@]}"
fi

PANEL_PORT=$("$INSTALL_DIR/venv/bin/python3" -c "import json; print(json.load(open('$CONFIG_DIR/config.json'))['port'])")

echo "==> Configuring firewall (SSH + panel port allowed BEFORE enabling, to avoid lockout)"
ufw allow 22/tcp >/dev/null
ufw allow "${PANEL_PORT}/tcp" >/dev/null
# 80/443 for every hosted site (PHP or Node) and for Let's Encrypt's HTTP-01
# challenge — without these, nginx vhosts exist but are unreachable from
# the internet regardless of DNS being correct.
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

echo "==> Setting up phpMyAdmin (real upstream tool, not custom-built)"
PMA_DIR="/usr/share/dearsoft-phpmyadmin"
PMA_PORT=$((PANEL_PORT + 1))
if [[ -d "$PMA_DIR" ]]; then
    echo "    Already installed at ${PMA_DIR} — skipping download."
else
    PMA_TMP=$(mktemp -d)
    curl -sL "https://files.phpmyadmin.net/phpMyAdmin/5.2.1/phpMyAdmin-5.2.1-all-languages.tar.gz" \
        -o "$PMA_TMP/pma.tar.gz"
    tar -xzf "$PMA_TMP/pma.tar.gz" -C "$PMA_TMP"
    mv "$PMA_TMP"/phpMyAdmin-5.2.1-all-languages "$PMA_DIR"
    rm -rf "$PMA_TMP"
fi

# TempDir for template caching — must live under /var, not /usr: php-fpm's
# systemd unit runs with ProtectSystem=full, which mounts /usr (and /boot,
# /etc) read-only inside php-fpm's own sandbox regardless of file ownership.
PMA_TMP_DIR="/var/lib/dearsoft-phpmyadmin-tmp"
mkdir -p "$PMA_TMP_DIR"
chown -R www-data:www-data "$PMA_TMP_DIR"
chmod 700 "$PMA_TMP_DIR"

# Control database ("configuration storage") for bookmarks/history/relations —
# without it PMA disables those extended features and nags on every page load.
PMA_CONTROL_PASS_FILE="$CONFIG_DIR/pma-control-pass"
if [[ -f "$PMA_CONTROL_PASS_FILE" ]]; then
    PMA_CONTROL_PASS=$(cat "$PMA_CONTROL_PASS_FILE")
else
    PMA_CONTROL_PASS=$(openssl rand -hex 16)
    echo "$PMA_CONTROL_PASS" > "$PMA_CONTROL_PASS_FILE"
    chmod 600 "$PMA_CONTROL_PASS_FILE"
fi
mysql -uroot << SQLSETUP
CREATE DATABASE IF NOT EXISTS phpmyadmin;
CREATE USER IF NOT EXISTS 'pma_control'@'localhost' IDENTIFIED BY '${PMA_CONTROL_PASS}';
GRANT ALL PRIVILEGES ON phpmyadmin.* TO 'pma_control'@'localhost';
FLUSH PRIVILEGES;
SQLSETUP
if [[ -f "$PMA_DIR/sql/create_tables.sql" ]]; then
    mysql -uroot phpmyadmin < "$PMA_DIR/sql/create_tables.sql" 2>/dev/null || true
fi

# A dedicated admin-level MySQL account so "Open phpMyAdmin" logs straight
# in showing every database — no separate login prompt, no re-entering
# credentials. This intentionally removes phpMyAdmin's own login screen as
# a barrier; the only things still standing between the internet and this
# account are the non-guessable port and the self-signed TLS cert (same
# tradeoff aaPanel/cPanel make with their own bundled phpMyAdmin).
PMA_ADMIN_PASS_FILE="$CONFIG_DIR/pma-admin-pass"
if [[ -f "$PMA_ADMIN_PASS_FILE" ]]; then
    PMA_ADMIN_PASS=$(cat "$PMA_ADMIN_PASS_FILE")
else
    PMA_ADMIN_PASS=$(openssl rand -hex 16)
    echo "$PMA_ADMIN_PASS" > "$PMA_ADMIN_PASS_FILE"
    chmod 600 "$PMA_ADMIN_PASS_FILE"
fi
mysql -uroot << SQLSETUP
CREATE USER IF NOT EXISTS 'dearsoft_pma_admin'@'localhost' IDENTIFIED BY '${PMA_ADMIN_PASS}';
ALTER USER 'dearsoft_pma_admin'@'localhost' IDENTIFIED BY '${PMA_ADMIN_PASS}';
GRANT ALL PRIVILEGES ON *.* TO 'dearsoft_pma_admin'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQLSETUP

# Exactly 32 bytes, per phpMyAdmin's own requirement — base64 of 32 random
# bytes is ~44 chars and triggers a "key is longer than necessary" warning.
if [[ -f "$CONFIG_DIR/pma-blowfish-secret" ]]; then
    BLOWFISH=$(cat "$CONFIG_DIR/pma-blowfish-secret")
else
    BLOWFISH=$(openssl rand -hex 16)
    echo "$BLOWFISH" > "$CONFIG_DIR/pma-blowfish-secret"
    chmod 600 "$CONFIG_DIR/pma-blowfish-secret"
fi

cat > "$PMA_DIR/config.inc.php" << PMACONFIG
<?php
\$cfg['blowfish_secret'] = '${BLOWFISH}';
\$i = 0;
\$i++;
\$cfg['Servers'][\$i]['auth_type'] = 'config';
\$cfg['Servers'][\$i]['user'] = 'dearsoft_pma_admin';
\$cfg['Servers'][\$i]['password'] = '${PMA_ADMIN_PASS}';
\$cfg['Servers'][\$i]['host'] = 'localhost';
\$cfg['Servers'][\$i]['compress'] = false;
\$cfg['Servers'][\$i]['AllowNoPassword'] = false;
\$cfg['Servers'][\$i]['controluser'] = 'pma_control';
\$cfg['Servers'][\$i]['controlpass'] = '${PMA_CONTROL_PASS}';
\$cfg['Servers'][\$i]['pmadb'] = 'phpmyadmin';
\$cfg['Servers'][\$i]['bookmarktable'] = 'pma__bookmark';
\$cfg['Servers'][\$i]['relation'] = 'pma__relation';
\$cfg['Servers'][\$i]['table_info'] = 'pma__table_info';
\$cfg['Servers'][\$i]['table_coords'] = 'pma__table_coords';
\$cfg['Servers'][\$i]['pdf_pages'] = 'pma__pdf_pages';
\$cfg['Servers'][\$i]['column_info'] = 'pma__column_info';
\$cfg['Servers'][\$i]['history'] = 'pma__history';
\$cfg['Servers'][\$i]['table_uiprefs'] = 'pma__table_uiprefs';
\$cfg['Servers'][\$i]['tracking'] = 'pma__tracking';
\$cfg['Servers'][\$i]['userconfig'] = 'pma__userconfig';
\$cfg['Servers'][\$i]['recent'] = 'pma__recent';
\$cfg['Servers'][\$i]['favorite'] = 'pma__favorite';
\$cfg['Servers'][\$i]['users'] = 'pma__users';
\$cfg['Servers'][\$i]['usergroups'] = 'pma__usergroups';
\$cfg['Servers'][\$i]['navigationhiding'] = 'pma__navigationhiding';
\$cfg['Servers'][\$i]['savedsearches'] = 'pma__savedsearches';
\$cfg['Servers'][\$i]['central_columns'] = 'pma__central_columns';
\$cfg['Servers'][\$i]['designer_settings'] = 'pma__designer_settings';
\$cfg['Servers'][\$i]['export_templates'] = 'pma__export_templates';
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['TempDir'] = '${PMA_TMP_DIR}';
PMACONFIG
chown -R www-data:www-data "$PMA_DIR"

PMA_SSL_DIR="$CONFIG_DIR/ssl-phpmyadmin"
if [[ ! -f "$PMA_SSL_DIR/pma.crt" ]]; then
    mkdir -p "$PMA_SSL_DIR"
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$PMA_SSL_DIR/pma.key" -out "$PMA_SSL_DIR/pma.crt" \
        -days 825 -subj "/CN=dearsoft-phpmyadmin" >/dev/null 2>&1
fi

PHP_SOCK="/run/php/php8.1-fpm.sock"
if [[ ! -S "$PHP_SOCK" ]]; then
    PHP_SOCK=$(find /run/php -name "*.sock" 2>/dev/null | head -1)
fi
if [[ -z "$PHP_SOCK" ]]; then
    echo "    WARNING: no php-fpm socket found — phpMyAdmin nginx vhost skipped." >&2
else
    cat > /etc/nginx/sites-available/dearsoft-phpmyadmin.conf << NGINXCONF
server {
    listen ${PMA_PORT} ssl;
    listen [::]:${PMA_PORT} ssl;
    ssl_certificate ${PMA_SSL_DIR}/pma.crt;
    ssl_certificate_key ${PMA_SSL_DIR}/pma.key;
    server_name _;
    root ${PMA_DIR};
    index index.php;

    # Large SQL/DB imports (default nginx 1m cap causes 413s on real dumps).
    client_max_body_size 1024m;

    location / {
        try_files \$uri \$uri/ =404;
    }
    location ~ \.php\$ {
        fastcgi_pass unix:${PHP_SOCK};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_read_timeout 300;
        include fastcgi_params;
    }
    location ~ /\.ht {
        deny all;
    }
}
NGINXCONF
    ln -sf /etc/nginx/sites-available/dearsoft-phpmyadmin.conf /etc/nginx/sites-enabled/dearsoft-phpmyadmin.conf

    # Match PHP's own upload/post limits to the nginx cap above — nginx alone
    # isn't enough, php-fpm's stock 2M/8M defaults would still truncate the import.
    PMA_PHP_VERSION=$(echo "$PHP_SOCK" | grep -oE 'php[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+')
    if [[ -n "$PMA_PHP_VERSION" && -d "/etc/php/${PMA_PHP_VERSION}/fpm/conf.d" ]]; then
        cat > "/etc/php/${PMA_PHP_VERSION}/fpm/conf.d/99-dearsoft-pma.ini" << PHPINI
upload_max_filesize = 1024M
post_max_size = 1024M
max_execution_time = 300
max_input_time = 300
memory_limit = 512M
PHPINI
        systemctl restart "php${PMA_PHP_VERSION}-fpm"
    fi

    nginx -t && systemctl reload nginx
    ufw allow "${PMA_PORT}/tcp" >/dev/null
    echo "    phpMyAdmin available on port ${PMA_PORT} (login with any MySQL user/password created via Databases)."
    "$INSTALL_DIR/venv/bin/python3" -c "
import json
path = '$CONFIG_DIR/config.json'
with open(path) as f:
    cfg = json.load(f)
cfg['pma_port'] = $PMA_PORT
with open(path, 'w') as f:
    json.dump(cfg, f, indent=2)
"
fi

echo "==> Installing scheduled Auto Backup cron job (daily 02:30)"
BACKUP_CRON_CMD="${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/scripts/run_scheduled_backups.py >> /var/log/ds-panel-backups.log 2>&1"
# Both crontab -l (no crontab yet on a fresh box) and grep -v (nothing left
# to filter) exit non-zero in the common case, which would otherwise abort
# the whole script here under `set -e` — before it ever reaches the
# systemd/service steps below. Neither failure means anything is wrong.
( { crontab -l 2>/dev/null || true; } | grep -v 'run_scheduled_backups.py' || true; echo "30 2 * * * ${BACKUP_CRON_CMD}" ) | crontab -

echo "==> Installing Backup Jobs poller (every 5 minutes — checks each job's own schedule)"
BACKUP_JOBS_CRON_CMD="${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/scripts/run_backup_jobs.py >> /var/log/ds-panel-backup-jobs.log 2>&1"
( { crontab -l 2>/dev/null || true; } | grep -v 'run_backup_jobs.py' || true; echo "*/5 * * * * ${BACKUP_JOBS_CRON_CMD}" ) | crontab -

echo "==> Installing Dropshipping fulfillment poller (every 10 minutes)"
FULFILLMENT_CRON_CMD="${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/scripts/run_fulfillment.py >> /var/log/ds-panel-fulfillment.log 2>&1"
( { crontab -l 2>/dev/null || true; } | grep -v 'run_fulfillment.py' || true; echo "*/10 * * * * ${FULFILLMENT_CRON_CMD}" ) | crontab -

echo "==> Installing systemd service (port ${PANEL_PORT})"
sed "s/__PANEL_PORT__/${PANEL_PORT}/" "$INSTALL_DIR/systemd/ds-panel.service" \
    > /etc/systemd/system/ds-panel.service

systemctl daemon-reload
systemctl enable --quiet ds-panel
systemctl restart ds-panel

sleep 1
if systemctl is-active --quiet ds-panel; then
    echo "==> DS Panel is running. Login details were printed above — save them now."
else
    echo "==> Service failed to start. Check: journalctl -u ds-panel -n 50" >&2
    exit 1
fi
