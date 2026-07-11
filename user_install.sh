#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="meshcore-packet-capture"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_PATH="$UNIT_DIR/${SERVICE_NAME}.service"

ENABLE_NOW=true
UPGRADE_PIP=true
ENABLE_LINGER=false
CONFIG_FILES=()

print_usage() {
    cat <<'EOF'
Usage: ./user_install.sh [options]

Options:
  --service-name NAME   systemd user service name (default: meshcore-packet-capture)
  --repo-dir PATH       repo checkout path (default: script directory)
  --config PATH         add a config file passed as --config PATH (repeatable)
  --no-enable-now       do not enable/start service immediately
  --no-upgrade-pip      skip pip self-upgrade in venv
  --enable-linger       run: sudo loginctl enable-linger <user>
  --help                show help

Notes:
  - If no --config flags are passed, the script auto-adds existing files from:
      /etc/meshcore-packet-capture/config.toml
      /etc/meshcore-packet-capture/config.d/*.toml
  - This script configures a per-user service (systemctl --user).
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
        --config)
            CONFIG_FILES+=("$2")
            shift 2
            ;;
        --no-enable-now)
            ENABLE_NOW=false
            shift
            ;;
        --no-upgrade-pip)
            UPGRADE_PIP=false
            shift
            ;;
        --enable-linger)
            ENABLE_LINGER=true
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
    echo "Do not run this script as root. It installs a user service." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found in PATH" >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found in PATH" >&2
    exit 1
fi

REPO_DIR="$(cd "$REPO_DIR" && pwd)"
VENV_DIR="$REPO_DIR/.venv"
UNIT_PATH="$UNIT_DIR/${SERVICE_NAME}.service"

if [[ ! -f "$REPO_DIR/pyproject.toml" ]]; then
    echo "pyproject.toml not found in repo path: $REPO_DIR" >&2
    exit 1
fi

if [[ ${#CONFIG_FILES[@]} -eq 0 ]]; then
    if [[ -f /etc/meshcore-packet-capture/config.toml ]]; then
        CONFIG_FILES+=("/etc/meshcore-packet-capture/config.toml")
    fi
    shopt -s nullglob
    for cfg in /etc/meshcore-packet-capture/config.d/*.toml; do
        CONFIG_FILES+=("$cfg")
    done
    shopt -u nullglob
fi

mkdir -p "$UNIT_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
    echo "Creating venv: $VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

if [[ "$UPGRADE_PIP" == true ]]; then
    echo "Upgrading pip in venv"
    "$VENV_DIR/bin/python" -m pip install --upgrade pip
fi

echo "Installing package from local checkout"
"$VENV_DIR/bin/python" -m pip install -e "$REPO_DIR"

exec_start="$VENV_DIR/bin/python -m meshcore_packet_capture"
for cfg in "${CONFIG_FILES[@]}"; do
    if [[ -f "$cfg" ]]; then
        exec_start+=" --config $cfg"
    else
        echo "Skipping missing config file: $cfg"
    fi
done

cat > "$UNIT_PATH" <<EOF
[Unit]
Description=MeshCore Packet Capture (user)
After=network-online.target bluetooth.target
Wants=network-online.target

[Service]
Type=exec
WorkingDirectory=$REPO_DIR
ExecStart=$exec_start
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
EOF

echo "Created unit: $UNIT_PATH"

systemctl --user daemon-reload

if [[ "$ENABLE_NOW" == true ]]; then
    systemctl --user enable --now "$SERVICE_NAME"
else
    systemctl --user enable "$SERVICE_NAME"
fi

if [[ "$ENABLE_LINGER" == true ]]; then
    echo "Enabling linger for user: $USER"
    sudo loginctl enable-linger "$USER"
fi

echo
echo "Done. Useful commands:"
echo "  systemctl --user status $SERVICE_NAME"
echo "  journalctl --user -u $SERVICE_NAME -f"
