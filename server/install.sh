#!/data/data/com.termux/files/usr/bin/bash
#
# Novastar LED Tile Diagnostic Tool — Termux Installer
# Run this inside Termux on your Novastar T10.
#
# Usage:
#   bash install.sh
#
# What it does:
#   1. Updates Termux packages
#   2. Installs Node.js
#   3. Installs npm dependencies
#   4. Creates a startup shortcut
#   5. Optionally starts the server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOLD="\e[1m"
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

log()  { echo -e "${BOLD}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   Novastar LED Diagnostic Tool — Installer       ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Step 1: Update Termux ────────────────────────────────────────────────────
log "Updating Termux package list..."
pkg update -y 2>/dev/null || warn "Package update had warnings (usually ok)"

# ── Step 2: Install Node.js ──────────────────────────────────────────────────
if command -v node &>/dev/null; then
  NODE_VER=$(node --version)
  ok "Node.js already installed: $NODE_VER"
else
  log "Installing Node.js..."
  pkg install nodejs -y || err "Failed to install Node.js"
  ok "Node.js installed: $(node --version)"
fi

# ── Step 3: npm dependencies ─────────────────────────────────────────────────
log "Installing npm dependencies..."
cd "$SCRIPT_DIR"
npm install --omit=dev 2>&1 | tail -5
ok "npm dependencies installed"

# ── Step 4: Create startup script ────────────────────────────────────────────
STARTUP="$HOME/start-nova-diag.sh"
cat > "$STARTUP" << 'STARTSCRIPT'
#!/data/data/com.termux/files/usr/bin/bash
# Start the Novastar diagnostic server
SERVER_DIR="$(dirname "$(realpath "$0")")/novastar-diagnostic/server"
if [ ! -d "$SERVER_DIR" ]; then
  # Try relative to home
  SERVER_DIR="$HOME/novastar-diagnostic/server"
fi
echo "Starting Novastar Diagnostic Server..."
echo "Open your browser to: http://192.168.43.1:8080"
echo "(Press Ctrl+C to stop)"
echo ""
exec node "$SERVER_DIR/server.js"
STARTSCRIPT
chmod +x "$STARTUP"
ok "Startup script created: $STARTUP"

# ── Step 5: Print network info ────────────────────────────────────────────────
echo ""
log "Network interfaces on this device:"
ip addr show 2>/dev/null | grep "inet " | awk '{print "    " $2}' || \
  ifconfig 2>/dev/null | grep "inet " | awk '{print "    " $2}' || \
  echo "    (could not detect IP — check Settings > Wi-Fi)"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║                  SETUP COMPLETE                  ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Start server:    ${BOLD}bash ~/start-nova-diag.sh${RESET}"
echo -e "  Or directly:     ${BOLD}node $SCRIPT_DIR/server.js${RESET}"
echo ""
echo -e "  Then on your phone/tablet:"
echo -e "  1. Connect to the T10's Wi-Fi AP"
echo -e "  2. Open browser to: ${BOLD}http://192.168.43.1:8080${RESET}"
echo ""
echo -e "  ${YELLOW}Note:${RESET} If 192.168.43.1 doesn't work, check the T10's"
echo -e "  actual Wi-Fi AP IP in Settings > Wi-Fi Hotspot."
echo ""

# ── Optional: start now ───────────────────────────────────────────────────────
read -r -p "Start the server now? [y/N] " START_NOW
if [[ "$START_NOW" =~ ^[Yy]$ ]]; then
  echo ""
  log "Starting server... (Ctrl+C to stop)"
  exec node "$SCRIPT_DIR/server.js"
fi
