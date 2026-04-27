#!/usr/bin/env bash
# ============================================================
#  setup.sh — Kali Linux / Debian Setup Script
#  Adaptive Intrusion Prevention System
# ============================================================
# Usage: sudo bash setup.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Root check ───────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  error "Run as root: sudo bash setup.sh"
fi

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     Adaptive IPS — Kali Linux Setup Script       ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Detect interface ─────────────────────────────────────────
IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}' || echo "eth0")
info "Detected primary interface: ${IFACE}"

# ── System update ─────────────────────────────────────────────
info "Updating package list …"
apt-get update -qq

# ── System dependencies ───────────────────────────────────────
info "Installing system packages …"
apt-get install -y -qq \
  python3 python3-pip python3-venv \
  iptables net-tools tcpdump \
  hping3 \
  libpcap-dev

success "System packages installed"

# ── Python virtual environment ────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"

info "Creating Python virtual environment at ${VENV_DIR} …"
python3 -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

info "Installing Python dependencies …"
pip install --quiet --upgrade pip
pip install --quiet -r "${PROJECT_DIR}/requirements.txt"

success "Python environment ready"

# ── iptables setup ────────────────────────────────────────────
info "Verifying iptables …"
iptables -L INPUT -n --line-numbers | head -5
success "iptables is functional"

# ── Config patch ──────────────────────────────────────────────
CONFIG_FILE="${PROJECT_DIR}/config.py"
info "Patching config.py with detected interface '${IFACE}' …"
sed -i "s/INTERFACE\s*=\s*.*$/INTERFACE = \"${IFACE}\"  # auto-detected by setup.sh/" \
    "${CONFIG_FILE}" 2>/dev/null || warn "Could not auto-patch interface"

# ── Systemd service (optional) ───────────────────────────────
SERVICE_FILE="/etc/systemd/system/adaptive-ips.service"
info "Creating systemd service at ${SERVICE_FILE} …"
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Adaptive Intrusion Prevention System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${VENV_DIR}/bin/python3 ${PROJECT_DIR}/main.py --interface ${IFACE}
Restart=on-failure
RestartSec=5s
StandardOutput=append:${PROJECT_DIR}/ips.log
StandardError=append:${PROJECT_DIR}/ips.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
success "Systemd service created (but NOT enabled)"

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Setup complete!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Interface :  ${BOLD}${IFACE}${NC}"
echo -e "  Python    :  ${BOLD}${VENV_DIR}/bin/python3${NC}"
echo -e "  Dashboard :  ${BOLD}http://localhost:5000${NC}"
echo ""
echo -e "${YELLOW}Start the IPS:${NC}"
echo -e "  cd ${PROJECT_DIR}"
echo -e "  sudo ${VENV_DIR}/bin/python3 main.py --interface ${IFACE}"
echo ""
echo -e "${YELLOW}Or start/stop as a service:${NC}"
echo -e "  sudo systemctl start adaptive-ips"
echo -e "  sudo systemctl stop  adaptive-ips"
echo -e "  sudo systemctl enable adaptive-ips   # auto-start on boot"
echo ""
echo -e "${YELLOW}Safe testing (dry-run, no actual iptables):${NC}"
echo -e "  sudo ${VENV_DIR}/bin/python3 main.py --dry-run"
echo ""
echo -e "${CYAN}Run simulated attack (from attacker VM):${NC}"
echo -e "  bash test_attack.sh <victim_ip> <interface>"
