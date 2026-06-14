#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  AegisMimic — Intruder Simulation Script
#  Run this INSIDE the aegis_attacker (Kali) container.
#
#  Simulates the behaviour of malware or a rogue script probing a
#  sensitive directory for credentials to exfiltrate.
#
#  Usage:
#    docker exec -it aegis_attacker bash /secure/backup/test_intruder.sh
#    OR inside the container:
#    bash /secure/backup/test_intruder.sh
# ─────────────────────────────────────────────────────────────────────

HONEY="/secure/backup"
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
RST='\033[0m'

echo -e "${YLW}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║     AegisMimic — Intruder Simulation Script     ║"
echo "  ║  Simulating unauthorized credential harvesting  ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${RST}"

echo -e "${RED}[*]${RST} Target directory: ${HONEY}"
echo -e "${RED}[*]${RST} Switch to Terminal 1 (daemon) to watch AegisMimic respond."
echo ""
sleep 1

# ── Step 1: Directory enumeration ────────────────────────────────────
echo -e "${RED}[1/4]${RST} Enumerating honey directory..."
ls -la ${HONEY}/
echo ""
sleep 2

# ── Step 2: Read SSH private key ─────────────────────────────────────
echo -e "${RED}[2/4]${RST} Attempting to read SSH private key..."
cat ${HONEY}/id_rsa 2>/dev/null && echo "" || echo "  (file missing)"
sleep 2

# ── Step 3: Harvest credentials — HOLDS FD OPEN ──────────────────────
# This is the critical step: holding the file descriptor open for 15
# seconds gives AegisMimic's retry loop time to resolve our PID and fire.
echo -e "${RED}[3/4]${RST} Harvesting AWS credentials (holding FD open 15s)..."
python3 -c "
import time, sys
try:
    f = open('${HONEY}/aws_credentials', 'r')
    data = f.read()
    print(data)
    print('  [simulated exfil] Sending to C2...')
    sys.stdout.flush()
    time.sleep(15)          # AegisMimic catches us here
    f.close()
    print('  [simulated exfil] Transfer complete.')
except KeyboardInterrupt:
    print('\n  [!] Process interrupted.')
" 2>/dev/null
echo ""

# ── Step 4: Try to copy files out ────────────────────────────────────
echo -e "${RED}[4/4]${RST} Attempting to stage files for exfiltration..."
cp ${HONEY}/database.env /tmp/stolen.env 2>/dev/null && \
    echo -e "  ${GRN}Copied database.env → /tmp/stolen.env${RST}" || \
    echo -e "  ${RED}Copy blocked or file missing${RST}"
echo ""

echo -e "${YLW}[*]${RST} Simulation complete. Check the daemon terminal for AegisMimic's response."
echo -e "${YLW}[*]${RST} Check audit/aegismimic.log on the host for the structured event record."
