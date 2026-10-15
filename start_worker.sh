#!/bin/bash
# start_worker.sh — запуск воркера на VPS
# Использование:
#   ./start_worker.sh                          # интерактивно
#   ./start_worker.sh --show-key               # показать worker public key
#   MASTER=10.10.0.1:9050 \
#   MASTER_KEY=abc... \
#   PASSWORD=xxx \
#   WG_ADDR=10.10.0.10 \
#   ./start_worker.sh

set -e
cd "$(dirname "$0")"

# ─── Config from env ────────────────────────────────────────────────
MASTER="${MASTER:-}"
MASTER_KEY="${MASTER_KEY:-}"
PASSWORD="${PASSWORD:-${LIVELIST_PASSWORD:-}}"
WG_ADDR="${WG_ADDR:-$(ip -4 addr show wg-mesh 2>/dev/null | \
    grep -oP 'inet \K[\d.]+' | head -1)}"
P2P_PORT="${P2P_PORT:-9100}"
WG_IFACE="${WG_IFACE:-wg-mesh}"

# ─── Colors ──────────────────────────────────────────────────────────
C='\033[1;36m'; Y='\033[1;33m'; G='\033[1;32m'; R='\033[0m'

# ─── Show key mode ──────────────────────────────────────────────────
if [[ "$1" == "--show-key" ]]; then
    ./run.sh show-worker-key
    exit 0
fi

# ─── Interactive prompts ─────────────────────────────────────────────
if [ -z "$MASTER" ]; then
    read -p "Master address [10.10.0.1:9050]: " MASTER
    MASTER="${MASTER:-10.10.0.1:9050}"
fi
if [ -z "$MASTER_KEY" ]; then
    read -p "Master public key (hex): " MASTER_KEY
fi
if [ -z "$PASSWORD" ]; then
    echo -n "2FA password: "
    read -s PASSWORD
    echo
fi

# ─── Check WG ────────────────────────────────────────────────────────
if ! ip link show "$WG_IFACE" &>/dev/null; then
    echo -e "${Y}[!] WireGuard $WG_IFACE не поднят${R}"
    echo -e "${Y}    Настрой /etc/wireguard/$WG_IFACE.conf${R}"
    read -p "Продолжить? [y/N] " ans
    [[ "$ans" != "y" ]] && exit 1
fi

# ─── Banner ──────────────────────────────────────────────────────────
echo -e "${C}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       LiveList WORKER (VPS)                          ║"
echo "╠══════════════════════════════════════════════════════╣"
printf "║  Master:   %-40s ║\n" "$MASTER"
printf "║  WG:       %-40s ║\n" "$WG_IFACE ($WG_ADDR)"
printf "║  P2P port: %-40s ║\n" "$P2P_PORT"
printf "║  2FA:      %-40s ║\n" "$([ -n "$PASSWORD" ] && echo ON || echo OFF)"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${R}"

# ─── Show worker public key ─────────────────────────────────────────
echo -e "${Y}[*] Worker public key (передай мастеру):${R}"
./run.sh show-worker-key
echo

# ─── Auto-update from git ───────────────────────────────────────────
if [ -d ".git" ] && [ "${AUTO_UPDATE:-1}" = "1" ]; then
    echo -e "${C}[*] Checking git updates...${R}"
    git fetch --quiet origin 2>/dev/null || true
    LOCAL=$(git rev-parse HEAD 2>/dev/null || echo "")
    REMOTE=$(git rev-parse @{u} 2>/dev/null || echo "")
    if [ -n "$LOCAL" ] && [ -n "$REMOTE" ] && [ "$LOCAL" != "$REMOTE" ]; then
        echo -e "${Y}[!] New version available. Pull? [y/N]${R}"
        read -p "" ans
        if [ "$ans" = "y" ]; then
            git pull --quiet
            echo -e "${G}[+] Updated${R}"
            exec "$0" "$@"
        fi
    fi
fi

# ─── Install deps ───────────────────────────────────────────────────
if [ ! -d ".venv" ]; then
    echo -e "${C}[*] Creating venv...${R}"
    python3 -m venv .venv
    .venv/bin/pip install --quiet -r requirements.txt
fi

# ─── Run ─────────────────────────────────────────────────────────────
export PYTHONUNBUFFERED=1
export LIVELIST_PASSWORD="$PASSWORD"

exec .venv/bin/python3 -m worker.agent \
    --master "$MASTER" \
    --master-key "$MASTER_KEY" \
    --password "$PASSWORD" \
    --wg-addr "$WG_ADDR" \
    --p2p-port "$P2P_PORT"