#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="meshcore-packet-capture"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
REMOVE_VENV=false
DISABLE_LINGER=false

print_usage() {
    cat <<'EOF'
Usage: ./user_uninstall.sh [options]

Options:
  --service-name NAME   systemd user service name (default: meshcore-packet-capture)
  --repo-dir PATH       repo checkout path (default: script directory)
  --remove-venv         remove local .venv in repo directory
  --disable-linger      run: sudo loginctl disable-linger <user>
  --help                show help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service-name)
            SERVICE_NAME="$2"
            shift 2
            ;;
        --repo-dir)
            REPO_DIR="$2"
            shift 2
            ;;
        --remove-venv)
            REMOVE_VENV=true
            shift
            ;;
        --disable-linger)
            DISABLE_LINGER=true
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_usage
            exit 1
            ;;
    esac
done

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "Do not run this script as root. It removes a user service." >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found in PATH" >&2
    exit 1
fi

REPO_DIR="$(cd "$REPO_DIR" && pwd)"
UNIT_PATH="$UNIT_DIR/${SERVICE_NAME}.service"

if systemctl --user list-unit-files | grep -q "^${SERVICE_NAME}\.service"; then
    systemctl --user disable --now "$SERVICE_NAME" || true
else
    systemctl --user stop "$SERVICE_NAME" || true
fi

if [[ -f "$UNIT_PATH" ]]; then
    rm -f "$UNIT_PATH"
    echo "Removed unit file: $UNIT_PATH"
fi

systemctl --user daemon-reload
systemctl --user reset-failed || true

if [[ "$REMOVE_VENV" == true ]]; then
    if [[ -d "$REPO_DIR/.venv" ]]; then
        rm -rf "$REPO_DIR/.venv"
        echo "Removed venv: $REPO_DIR/.venv"
    fi
fi

if [[ "$DISABLE_LINGER" == true ]]; then
    echo "Disabling linger for user: $USER"
    sudo loginctl disable-linger "$USER"
fi

echo
echo "Done. User service removed: $SERVICE_NAME"
