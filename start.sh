#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# LAN Stream v2 Launcher
# Multi-worker · Dynamic PIN Auth · Session Manager
# ─────────────────────────────────────────────────────────────────────────────

PORT=${1:-8888}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── WORKERS ───────────────────────────────────────────────────────────────────
# Each worker handles one complete request (stream / browse / download).
# 4 workers = up to 4 devices streaming simultaneously without blocking.
# Requires PHP 7.4+ for PHP_CLI_SERVER_WORKERS support.
export PHP_CLI_SERVER_WORKERS=4

# ── REQUIRED DIRECTORIES ──────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/videos"
mkdir -p "$SCRIPT_DIR/logs"
mkdir -p "$SCRIPT_DIR/data/sess"
chmod 700 "$SCRIPT_DIR/data/sess"

echo ""
echo "  ⚡  LAN Stream v2"
echo "  ─────────────────────────────────────────────────────"
echo ""
echo "  📡  Share this address with devices on your network:"
echo ""

if command -v ip &>/dev/null; then
    ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | while read -r ip; do
        echo "       http://$ip:$PORT/auth.php"
    done
elif command -v ifconfig &>/dev/null; then
    ifconfig | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $2}' | while read -r ip; do
        echo "       http://$ip:$PORT/auth.php"
    done
fi

echo ""
echo "  ⚙  Workers  : $PHP_CLI_SERVER_WORKERS concurrent streams supported"
echo "  🔒  Auth     : Dynamic PIN — each device gets a unique one-time PIN"
echo "               PIN is printed HERE in this terminal window"
echo "  ⊞  Sessions : Ctrl+Shift+K in the browser to manage sessions"
echo ""
echo "  ─────────────────────────────────────────────────────"
echo "  [Ctrl+C to stop]"
echo ""

php -S "0.0.0.0:$PORT" -t "$SCRIPT_DIR"
