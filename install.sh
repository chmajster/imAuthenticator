#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

APP_NAME="imAuthenticator"
DEFAULT_PORT=80
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PUBLIC_DIR="$SCRIPT_DIR/public"
STATE_DIR="/etc/imauthenticator"
PORT_FILE="$STATE_DIR/port"
APACHE_SITE_NAME="000-imauthenticator.conf"
APACHE_SITE_AVAILABLE="/etc/apache2/sites-available/$APACHE_SITE_NAME"
APACHE_PORT_CONF="/etc/apache2/conf-available/imauthenticator-port.conf"
PORT=""
PORT_EXPLICIT=0
COMMAND="install"

info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
imAuthenticator installer / lifecycle helper

Usage:
  sudo ./install.sh install [--port PORT]
  sudo ./install.sh update [--port PORT]
  sudo ./install.sh status
  ./install.sh help

Commands:
  install             Install/configure Apache, PHP dependencies and imAuthenticator.
                      If --port is omitted, HTTP port 80 is used.

  update              Update the Git checkout, install Composer dependencies and refresh
                      Apache configuration. If --port is omitted, the currently configured
                      port is preserved. If there is no saved port, port 80 is used.

  status              Show the configured HTTP port and Apache/PHP status.

  help                Show this help.

Options:
  --port PORT         HTTP listen port, from 1 to 65535.

Examples:
  sudo ./install.sh install
  sudo ./install.sh install --port 8080
  sudo ./install.sh update
  sudo ./install.sh update --port 80
  sudo ./install.sh update --port 8080

Port behavior:
  install             default: 80
  install --port N    use N
  update              preserve existing port
  update --port N     change the existing installation to N

The selected port is persisted in:
  /etc/imauthenticator/port
EOF
}

require_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this command as root, for example: sudo ./install.sh $COMMAND"
}

validate_port() {
    [[ "$PORT" =~ ^[0-9]+$ ]] || die "Invalid port: $PORT"
    (( PORT >= 1 && PORT <= 65535 )) || die "Port must be between 1 and 65535."
}

load_saved_port() {
    if [[ -r "$PORT_FILE" ]]; then
        local saved
        saved="$(tr -d '[:space:]' < "$PORT_FILE")"
        if [[ "$saved" =~ ^[0-9]+$ ]] && (( saved >= 1 && saved <= 65535 )); then
            printf '%s' "$saved"
            return
        fi
        warn "Ignoring invalid saved port in $PORT_FILE."
    fi
    printf '%s' "$DEFAULT_PORT"
}

parse_args() {
    if (($# > 0)) && [[ "$1" != --* ]]; then
        COMMAND="$1"
        shift
    fi

    while (($#)); do
        case "$1" in
            --port)
                (($# >= 2)) || die "--port requires a value."
                PORT="$2"
                PORT_EXPLICIT=1
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    case "$COMMAND" in
        install)
            [[ -n "$PORT" ]] || PORT="$DEFAULT_PORT"
            validate_port
            ;;
        update)
            [[ -n "$PORT" ]] || PORT="$(load_saved_port)"
            validate_port
            ;;
        status|help)
            ;;
        *)
            die "Unknown command: $COMMAND"
            ;;
    esac
}

check_application_tree() {
    [[ -d "$PUBLIC_DIR" ]] || die "Missing public directory: $PUBLIC_DIR"
    [[ -f "$PUBLIC_DIR/index.php" ]] || die "Missing public/index.php. Run this script from the imAuthenticator repository."
    [[ -f "$SCRIPT_DIR/composer.json" ]] || die "Missing composer.json."
}

install_packages_debian() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y \
        apache2 \
        libapache2-mod-php \
        php \
        php-cli \
        php-mysql \
        php-mbstring \
        php-curl \
        php-xml \
        php-zip \
        composer \
        git \
        ca-certificates
}

ensure_dependencies() {
    if ! command -v apache2ctl >/dev/null 2>&1 || ! command -v php >/dev/null 2>&1 || ! command -v composer >/dev/null 2>&1; then
        if command -v apt-get >/dev/null 2>&1; then
            info "Installing Apache, PHP and Composer dependencies."
            install_packages_debian
        else
            die "Automatic dependency installation currently requires a Debian/Ubuntu-compatible system. Install Apache, PHP >= 8.2, PDO MySQL, mbstring, OpenSSL, JSON and Composer manually."
        fi
    fi

    local php_version
    php_version="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)"
    [[ -n "$php_version" ]] || die "PHP is unavailable."
    if ! php -r 'exit(PHP_VERSION_ID >= 80200 ? 0 : 1);'; then
        die "PHP >= 8.2 is required; detected $php_version."
    fi

    php -m | grep -qi '^PDO$' || die "PHP PDO extension is required."
    php -m | grep -qi '^pdo_mysql$' || die "PHP pdo_mysql extension is required."
    php -m | grep -qi '^openssl$' || die "PHP OpenSSL extension is required."
    php -m | grep -qi '^json$' || die "PHP JSON extension is required."
    php -m | grep -qi '^mbstring$' || die "PHP mbstring extension is required."
}

install_composer_dependencies() {
    info "Installing Composer dependencies."
    COMPOSER_ALLOW_SUPERUSER=1 composer install \
        --working-dir="$SCRIPT_DIR" \
        --no-dev \
        --prefer-dist \
        --no-interaction \
        --optimize-autoloader
}

configure_apache_port() {
    mkdir -p "$STATE_DIR"
    printf '%s\n' "$PORT" > "$PORT_FILE"
    chmod 0644 "$PORT_FILE"

    if [[ "$PORT" == "80" ]]; then
        if [[ -e "$APACHE_PORT_CONF" ]]; then
            a2disconf imauthenticator-port >/dev/null 2>&1 || true
            rm -f "$APACHE_PORT_CONF"
        fi
    else
        cat > "$APACHE_PORT_CONF" <<EOF
# Managed by imAuthenticator install.sh.
Listen $PORT
EOF
        a2enconf imauthenticator-port >/dev/null
    fi
}

configure_apache_site() {
    local escaped_public
    escaped_public="${PUBLIC_DIR//&/\\&}"

    cat > "$APACHE_SITE_AVAILABLE" <<EOF
# Managed by imAuthenticator install.sh.
<VirtualHost *:$PORT>
    ServerName localhost
    DocumentRoot "$PUBLIC_DIR"

    <Directory "$PUBLIC_DIR">
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
        DirectoryIndex index.php
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/imauthenticator-error.log
    CustomLog \${APACHE_LOG_DIR}/imauthenticator-access.log combined
</VirtualHost>
EOF

    a2enmod rewrite >/dev/null
    a2ensite "$APACHE_SITE_NAME" >/dev/null

    # imAuthenticator is intended to be the default application on the selected HTTP port.
    # Disable Apache's stock placeholder site so requests to the server IP reach this app.
    if [[ -e /etc/apache2/sites-enabled/000-default.conf ]]; then
        a2dissite 000-default.conf >/dev/null || true
    fi

    apache2ctl configtest
    systemctl enable apache2 >/dev/null 2>&1 || true
    systemctl restart apache2
}

sync_git_checkout() {
    if ! command -v git >/dev/null 2>&1; then
        warn "git is not installed; skipping source update."
        return
    fi
    if [[ ! -d "$SCRIPT_DIR/.git" ]]; then
        warn "$SCRIPT_DIR is not a Git checkout; skipping git pull."
        return
    fi

    if ! git -C "$SCRIPT_DIR" diff --quiet || ! git -C "$SCRIPT_DIR" diff --cached --quiet; then
        die "The repository contains uncommitted changes. Commit/stash them before running update."
    fi

    info "Updating repository."
    git -C "$SCRIPT_DIR" pull --ff-only
}

run_install() {
    require_root
    check_application_tree
    ensure_dependencies
    install_composer_dependencies
    configure_apache_port
    configure_apache_site

    ok "$APP_NAME is configured on HTTP port $PORT."
    printf 'Open: http://<server-address>'
    if [[ "$PORT" != "80" ]]; then
        printf ':%s' "$PORT"
    fi
    printf '/\n'
    printf 'The browser installer is available at /install.php until config/config.php is created.\n'
}

run_update() {
    require_root
    check_application_tree
    ensure_dependencies
    sync_git_checkout
    install_composer_dependencies
    configure_apache_port
    configure_apache_site

    if (( PORT_EXPLICIT )); then
        ok "$APP_NAME updated and configured on HTTP port $PORT."
    else
        ok "$APP_NAME updated; existing HTTP port $PORT was preserved."
    fi
}

run_status() {
    local current_port
    current_port="$(load_saved_port)"
    printf '%s\n' "$APP_NAME"
    printf 'Configured HTTP port: %s\n' "$current_port"
    printf 'Application path: %s\n' "$SCRIPT_DIR"
    if command -v php >/dev/null 2>&1; then
        printf 'PHP: %s\n' "$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)"
    else
        printf 'PHP: not installed\n'
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet apache2; then
        printf 'Apache: active\n'
    else
        printf 'Apache: inactive or unavailable\n'
    fi
}

main() {
    parse_args "$@"
    case "$COMMAND" in
        install) run_install ;;
        update) run_update ;;
        status) run_status ;;
        help) usage ;;
    esac
}

main "$@"
