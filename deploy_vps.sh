#!/bin/bash
# deploy_vps.sh — полностью автоматическое развёртывание воркера на VPS
#
# Использование:
#   GITHUB_URL=https://github.com/you/livelist-worker.git ./deploy_vps.sh
#
# Или интерактивно — просто запусти ./deploy_vps.sh

set -e

# ═════════════════════════════════════════════════════════════════════
# ⚙️  НАСТРОЙКИ — ЗАПОЛНИ ЭТИ ПЕРЕМЕННЫЕ
# ═════════════════════════════════════════════════════════════════════

GITHUB_URL="${GITHUB_URL:-https://github.com/YOUR_USER/livelist-worker.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/livelist-worker}"
WG_IFACE="${WG_IFACE:-wg-mesh}"
WG_ADDR="${WG_ADDR:-10.10.0.10}"     # уникальный для каждого VPS!
P2P_PORT="${P2P_PORT:-9100}"

# Master info — заполнится интерактивно если не задано
MASTER_HOST="${MASTER_HOST:-}"
MASTER_PORT="${MASTER_PORT:-51820}"
MASTER_WG_PUBKEY="${MASTER_WG_PUBKEY:-}"
MASTER_LIVELIST_KEY="${MASTER_LIVELIST_KEY:-}"
PASSWORD="${PASSWORD:-}"

# ═════════════════════════════════════════════════════════════════════
# Цвета
# ═════════════════════════════════════════════════════════════════════

C='\033[1;36m'; Y='\033[1;33m'; G='\033[1;32m'; R='\033[1;31m'; N='\033[0m'

echo -e "${C}"
cat << 'BANNER'
╔══════════════════════════════════════════════════════════╗
║        LiveList WORKER — auto deployment (VPS)           ║
╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${N}"

# ═════════════════════════════════════════════════════════════════════
# 1. Интерактивный ввод если переменные не заданы
# ═════════════════════════════════════════════════════════════════════

echo -e "${Y}[1/8] Настройка параметров...${N}"

if [ -z "$MASTER_HOST" ]; then
    read -p "Master public IP: " MASTER_HOST
fi
if [ -z "$MASTER_WG_PUBKEY" ]; then
    read -p "Master WireGuard public key: " MASTER_WG_PUBKEY
fi
if [ -z "$MASTER_LIVELIST_KEY" ]; then
    read -p "Master LiveList public key (hex): " MASTER_LIVELIST_KEY
fi
if [ -z "$PASSWORD" ]; then
    read -sp "2FA password: " PASSWORD
    echo
fi

echo "  → Master: $MASTER_HOST:$MASTER_PORT"
echo "  → WG addr: $WG_ADDR"

# ═════════════════════════════════════════════════════════════════════
# 2. Проверка системы
# ═════════════════════════════════════════════════════════════════════

echo -e "${Y}[2/8] Проверка системы...${N}"

if ! command -v apt >/dev/null; then
    echo -e "${R}Требуется Debian/Ubuntu${N}"
    exit 1
fi

# ═════════════════════════════════════════════════════════════════════
# 3. Установка зависимостей
# ═════════════════════════════════════════════════════════════════════

echo -e "${Y}[3/8] Установка зависимостей...${N}"

sudo apt update -qq
sudo apt install -y -qq \
    python3 python3-pip python3-venv \
    wireguard wireguard-tools \
    git curl jq 2>&1 | tail -3

# ═════════════════════════════════════════════════════════════════════
# 4. Клонирование
# ═════════════════════════════════════════════════════════════════════

echo -e "${Y}[4/8] Клонирование репозитория...${N}"

if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR"
    git pull --quiet
else
    git clone --quiet "$GITHUB_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# ═════════════════════════════════════════════════════════════════════
# 5. Python venv
# ═════════════════════════════════════════════════════════════════════

echo -e "${Y}[5/8] Python venv...${N}"

if [ ! -d "$INSTALL_DIR/.venv" ]; then
    python3 -m venv "$INSTALL_DIR/.venv"
fi
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -r requirements.txt

# ═════════════════════════════════════════════════════════════════════
# 6. WireGuard setup
# ═════════════════════════════════════════════════════════════════════

echo -e "${Y}[6/8] WireGuard setup...${N}"

WG_CONF="/etc/wireguard/${WG_IFACE}.conf"

if [ ! -f "$WG_CONF" ]; then
    WG_PRIV=$(wg genkey)
    WG_PUB=$(echo "$WG_PRIV" | wg pubkey)

    sudo mkdir -p /etc/wireguard
    sudo tee "$WG_CONF" > /dev/null <<EOF
[Interface]
PrivateKey = $WG_PRIV
Address = $WG_ADDR/24

[Peer]
PublicKey = $MASTER_WG_PUBKEY
Endpoint = $MASTER_HOST:$MASTER_PORT
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
EOF
    sudo chmod 600 "$WG_CONF"

    echo "  → Создан $WG_CONF"
    echo "  → Worker WG public: $WG_PUB"
    echo "$WG_PUB" > "$INSTALL_DIR/config/wg_worker_pub.txt"
    echo
    echo -e "${Y}  ⚠️  ЭТОТ КЛЮЧ НУЖНО ДОБАВИТЬ НА МАСТЕРЕ в $WG_CONF:${N}"
    echo "    [Peer]"
    echo "    PublicKey = $WG_PUB"
    echo "    AllowedIPs = $WG_ADDR/32"
else
    echo "  → Использую существующий"
fi

# Поднять
if ! ip link show "$WG_IFACE" &>/dev/null; then
    sudo wg-quick up "$WG_IFACE"
    sleep 2
fi
sudo systemctl enable "wg-quick@${WG_IFACE}" 2>/dev/null || true

# Проверка связи
echo -n "  → Проверка связи с мастером... "
if ping -c 2 -W 3 10.10.0.1 >/dev/null 2>&1; then
    echo -e "${G}OK${N}"
else
    echo -e "${R}НЕТ СВЯЗИ${N}"
    echo "    Проверь на мастере: добавлен ли worker WG pubkey"
fi

# ═════════════════════════════════════════════════════════════════════
# 7. Генерация worker keys + env
# ═════════════════════════════════════════════════════════════════════

echo -e "${Y}[7/8] Worker LiveList keys...${N}"

cd "$INSTALL_DIR"

# Генерируем ключи
WORKER_PUB=$(
    "$INSTALL_DIR/.venv/bin/python3" -c "
import sys; sys.path.insert(0, '.')
from worker.agent import WorkerAgent
a = WorkerAgent('0.0.0.0:1', '00'*32)
print(a.static_pub.hex())
"
)

echo "  → Worker LiveList pubkey: $WORKER_PUB"

# Сохраняем env
cat > "$HOME/.livelist_worker.env" <<EOF
export MASTER="$MASTER_HOST:9050"
export MASTER_KEY="$MASTER_LIVELIST_KEY"
export PASSWORD="$PASSWORD"
export WG_ADDR="$WG_ADDR"
export P2P_PORT="$P2P_PORT"
EOF
chmod 600 "$HOME/.livelist_worker.env"

# ═════════════════════════════════════════════════════════════════════
# 8. Systemd service
# ═════════════════════════════════════════════════════════════════════

echo -e "${Y}[8/8] Systemd service...${N}"

sudo tee /etc/systemd/system/livelist-worker.service > /dev/null <<EOF
[Unit]
Description=LiveList Worker
After=network-online.target wg-quick@${WG_IFACE}.service
Wants=network-online.target wg-quick@${WG_IFACE}.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$HOME/.livelist_worker.env
ExecStart=$INSTALL_DIR/.venv/bin/python3 -m worker.agent \
    --master \${MASTER} \
    --master-key \${MASTER_KEY} \
    --password \${PASSWORD} \
    --wg-addr \${WG_ADDR} \
    --p2p-port \${P2P_PORT}
Restart=always
RestartSec=10
StandardOutput=append:$INSTALL_DIR/logs/systemd.log
StandardError=append:$INSTALL_DIR/logs/systemd.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable livelist-worker

# ═════════════════════════════════════════════════════════════════════
# Готово
# ═════════════════════════════════════════════════════════════════════

echo
echo -e "${G}"
cat << EOF
╔══════════════════════════════════════════════════════════╗
║              WORKER READY                                ║
╠══════════════════════════════════════════════════════════╣
║  Install:       $INSTALL_DIR
║  WG:            $WG_IFACE ($WG_ADDR)
║  P2P port:      $P2P_PORT
║
║  ⚠️  ДОБАВЬ НА МАСТЕРЕ:
║   1. WireGuard peer (см. выше — wg_worker_pub.txt)
║   2. LiveList whitelist:
║      $WORKER_PUB
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${N}"

echo -e "${Y}"
cat << 'EOF'
🚀 СЛЕДУЮЩИЕ ШАГИ:

1. На мастере (Kali):
   cd ~/livelist-master
   nano config/workers.json
   # Добавь worker pubkey в "allowed"

   # Перезапусти или подожди 30s

2. Здесь запусти сервис:
   sudo systemctl start livelist-worker
   journalctl -u livelist-worker -f

3. Если нужно — сначала подключись к мастеру для auto-peer setup:
   source ~/.livelist_worker.env
   cd $INSTALL_DIR
   ./run.sh worker --master $MASTER --master-key $MASTER_KEY \
       --password $PASSWORD --wg-addr $WG_ADDR --p2p-port $P2P_PORT

EOF
echo -e "${N}"