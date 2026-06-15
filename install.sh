#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  AegisMimic — Production Installer
#  Installs AegisMimic as a systemd service on Linux.
#
#  Usage:
#    sudo ./install.sh
#    sudo ./install.sh --watch /home/user/keys --webhook https://hooks.slack.com/...
#    sudo ./install.sh --uninstall
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
INSTALL_DIR="/opt/aegismimic"
CONFIG_DIR="/etc/aegismimic"
LOG_DIR="/var/log/aegismimic"
SERVICE_FILE="/etc/systemd/system/aegismimic.service"
WATCH_DIR="/opt/aegismimic/honey"
WEBHOOK=""
UNINSTALL=false

# ── Colours ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; RST='\033[0m'
info()  { echo -e "${BLU}[*]${RST} $*"; }
ok()    { echo -e "${GRN}[+]${RST} $*"; }
warn()  { echo -e "${YLW}[!]${RST} $*"; }
error() { echo -e "${RED}[!]${RST} $*"; exit 1; }

# ── Parse args ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --watch)     WATCH_DIR="$2";  shift 2 ;;
        --webhook)   WEBHOOK="$2";    shift 2 ;;
        --uninstall) UNINSTALL=true;  shift ;;
        *) error "Unknown argument: $1" ;;
    esac
done

# ── Must be root ──────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "Run as root: sudo ./install.sh"

# ── Uninstall ─────────────────────────────────────────────────────────
if $UNINSTALL; then
    info "Uninstalling AegisMimic..."
    systemctl stop aegismimic    2>/dev/null || true
    systemctl disable aegismimic 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    warn "Files in ${INSTALL_DIR} and ${LOG_DIR} preserved. Remove manually if needed."
    ok "AegisMimic uninstalled."
    exit 0
fi

echo ""
echo "  ╔═══════════════════════════════════════════════════╗"
echo "  ║           AegisMimic Installer                    ║"
echo "  ║  I Don't Want To Get Hacked,                      ║"
echo "  ║  So I'll Max Out My Camouflage!                   ║"
echo "  ╚═══════════════════════════════════════════════════╝"
echo ""

# ── Check Python 3.9+ ─────────────────────────────────────────────────
info "Checking Python version..."
PYTHON=$(command -v python3 || error "python3 not found. Install it first.")
PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")
[[ $PY_MAJOR -ge 3 && $PY_MINOR -ge 9 ]] || error "Python 3.9+ required (found $PY_VER)"
ok "Python $PY_VER found."

# ── Install Python dependencies ───────────────────────────────────────
info "Installing Python dependencies..."
pip3 install -q inotify==0.2.10 pyyaml --break-system-packages 2>/dev/null || \
pip3 install -q inotify==0.2.10 pyyaml
ok "Dependencies installed."

# ── Create directories ────────────────────────────────────────────────
info "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR/snapshots" "$WATCH_DIR"
ok "Directories created."

# ── Copy project files ────────────────────────────────────────────────
info "Installing to ${INSTALL_DIR}..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR"/{aegismimic.py,core,audit,requirements.txt} "$INSTALL_DIR/"
chmod +x "${INSTALL_DIR}/aegismimic.py"
ok "Files installed."

# ── Copy config (don't overwrite existing) ───────────────────────────
if [[ ! -f "${CONFIG_DIR}/policy.yaml" ]]; then
    cp "$SCRIPT_DIR/config/policy.yaml" "${CONFIG_DIR}/policy.yaml"
    ok "Policy config installed to ${CONFIG_DIR}/policy.yaml"
    warn "Edit ${CONFIG_DIR}/policy.yaml to set your authorized users and processes."
else
    warn "Existing policy at ${CONFIG_DIR}/policy.yaml preserved."
fi

# ── Write systemd service ─────────────────────────────────────────────
info "Installing systemd service..."
cat > "$SERVICE_FILE" << SERVICE
[Unit]
Description=AegisMimic — Honey Directory Engine
Documentation=https://github.com/rithinkrishnakv
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/aegismimic.py \\
    --watch ${WATCH_DIR} \\
    --config ${CONFIG_DIR}/policy.yaml \\
    --log-file ${LOG_DIR}/audit.log \\
    --snapshot-dir ${LOG_DIR}/snapshots$([ -n "$WEBHOOK" ] && echo " \\\n    --webhook ${WEBHOOK}")
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegismimic

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable aegismimic
ok "systemd service installed and enabled."

# ── Populate honey directory ──────────────────────────────────────────
info "Populating honey directory at ${WATCH_DIR}..."
$PYTHON "${INSTALL_DIR}/aegismimic.py" --demo 2>/dev/null | head -1 || true
# Run demo setup directly
$PYTHON -c "
from pathlib import Path
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from aegismimic import setup_demo
setup_demo(Path('${WATCH_DIR}'))
" 2>/dev/null || warn "Could not auto-populate honey directory. Run --demo manually."

# ── Done ──────────────────────────────────────────────────────────────
echo ""
ok "AegisMimic installed successfully!"
echo ""
echo "  Next steps:"
echo "  1. Edit ${CONFIG_DIR}/policy.yaml — add your username to authorized_rules"
echo "  2. Start the service:  systemctl start aegismimic"
echo "  3. Check status:       systemctl status aegismimic"
echo "  4. View logs:          journalctl -u aegismimic -f"
echo "  5. Audit log:          tail -f ${LOG_DIR}/audit.log | python3 -m json.tool"
echo ""
echo "  Honey directory (the trap): ${WATCH_DIR}"
echo "  Policy:                     ${CONFIG_DIR}/policy.yaml"
echo "  Logs:                       ${LOG_DIR}/"
echo ""
