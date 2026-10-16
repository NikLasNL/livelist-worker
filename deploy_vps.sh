#!/bin/bash
# deploy_vps.sh — развёртывание воркера с auto-discovery
#
# MASTER_HOST НЕ нужен — discovery найдёт автоматически.
# Нужен только RELAY_HOST (IP первого VPS/Kali в WG).
#
# Использование:
#   export GITHUB_URL="https://github.com/YOU/livelist-worker.git"
#   export BOOTSTRAP_TOKEN="XXXX-XXXX-XXXX-XXXX-XXXX"
#   export WG_ADDR="10.10.0.10"
#   export RELAY_HOST="10.10.0.1"    # Kali или VPS-1 (WG addr)
#   ./deploy_vps.sh

set -e

GITHUB_URL="${GITHUB_URL:-https://github.com/NikLasNL/livelist-worker.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/livelist-worker}"
WG_IFACE="${WG_IFACE:-wg-mesh}"
WG_ADDR="${WG_ADDR:-10.10.0.10}"
WG_PORT="${WG_PORT:-51820}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-}"
RELAY_HOST="${RELAY_HOST:-10.10.0.1}"
SECRETS_DIR="${SECRETS_DIR:-$HOME/livelist-secrets}"
ENV_FILE="$HOME/.livelist_worker.env"

C='\033[1;36m'; Y='\033[1;33m'; G='\033[1;32m'; R='\033[1;31m'; N='\033[0m'
ok()    { echo -e "${G}  ✓ $*${N}"; }
fail()  { echo -e "${R}  ✗ $*${N}"; }
warn()  { echo -e "${Y}  ⚠ $*${N}"; }
info()  { echo -e "${C}  → $*${N}"; }
step()  { echo -e "\n${C}[$1] $2${N}"; }

echo -e "${C}"
cat << 'BANNER'
╔══════════════════════════════════════════════════════════╗
║   LiveList WORKER — deploy with auto-discovery           ║
╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${N}"

# ─── Ввод ────────────────────────────────────────────────────────────

if [ -z "$BOOTSTRAP_TOKEN" ]; then
    read -p "Bootstrap token (XXXX-XXXX-XXXX-XXXX-XXXX): " BOOTSTRAP_TOKEN
fi

if [ -z "$RELAY_HOST" ]; then
    read -p "Relay host (WG addr, default=10.10.0.1): " RELAY_HOST
    RELAY_HOST="${RELAY_HOST:-10.10.0.1}"
fi

# ─── 1. Зависимости ──────────────────────────────────────────────────
step "1/8" "Зависимости"

sudo apt update -qq
sudo apt install -y -qq \
    python3 python3-pip python3-venv \
    wireguard wireguard-tools \
    git curl jq iputils-ping 2>&1 | tail -2
ok "apt packages"

# ─── 2. Клонирование ─────────────────────────────────────────────────
step "2/8" "Git clone/pull"

mkdir -p "$(dirname "$INSTALL_DIR")"

if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR"
    git pull --quiet || true
    ok "Updated: $(git rev-parse --short HEAD 2>/dev/null)"
else
    git clone --quiet "$GITHUB_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    ok "Cloned"
fi

# Проверка структуры
for f in shared/crypto.py shared/protocol.py shared/ca.py \
         shared/directory.py shared/bootstrap.py shared/discovery.py \
         worker/agent.py worker/p2p.py worker/loader.py \
         worker/executor.py worker/relay.py; do
    if [ ! -f "$INSTALL_DIR/$f" ]; then
        fail "Missing: $f"
        exit 1
    fi
done
ok "Структура OK"

# ─── 3. Python venv ──────────────────────────────────────────────────
step "3/8" "Python venv"

[ ! -d ".venv" ] && python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
ok "venv + requirements"

# ─── 4. WireGuard ────────────────────────────────────────────────────
step "4/8" "WireGuard"

mkdir -p "$SECRETS_DIR"

WG_PRIV_PATH="$SECRETS_DIR/wg_worker_priv.txt"
if [ ! -f "$WG_PRIV_PATH" ]; then
    wg genkey > "$WG_PRIV_PATH"
    chmod 600 "$WG_PRIV_PATH"
fi
WG_PRIV=$(cat "$WG_PRIV_PATH")
WG_PUB=$(echo "$WG_PRIV" | wg pubkey)

echo "$WG_PUB" > "$SECRETS_DIR/wg_worker_pub.txt"
chmod 600 "$SECRETS_DIR/wg_worker_pub.txt"

info "Worker WG pubkey: $WG_PUB"
info "Add to $RELAY_HOST /etc/wireguard/${WG_IFACE}.conf:"
info "  [Peer]"
info "  PublicKey = $WG_PUB"
info "  AllowedIPs = $WG_ADDR/32"

# Определяем relay WG pubkey
# Первый VPS подключается к Kali (10.10.0.1)
# Второй VPS подключается к VPS-1 (10.10.0.10) — но там другой pubkey
# Пока hardcoded — запрос у пользователя
RELAY_WG_PUB="${RELAY_WG_PUB:-}"

if [ -z "$RELAY_WG_PUB" ]; then
    read -p "Relay WireGuard pubkey: " RELAY_WG_PUB
fi

sudo mkdir -p /etc/wireguard
if [ ! -f "/etc/wireguard/${WG_IFACE}.conf" ]; then
    sudo tee "/etc/wireguard/${WG_IFACE}.conf" > /dev/null <<EOF
[Interface]
PrivateKey = $WG_PRIV
Address = $WG_ADDR/24

[Peer]
PublicKey = $RELAY_WG_PUB
Endpoint = ${RELAY_HOST}:${WG_PORT}
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
EOF
    sudo chmod 600 "/etc/wireguard/${WG_IFACE}.conf"
    ok "Создан WG конфиг"
fi

if ! ip link show "$WG_IFACE" &>/dev/null; then
    sudo wg-quick up "$WG_IFACE"
fi
sudo systemctl enable "wg-quick@${WG_IFACE}" 2>/dev/null || true
ok "WG up + enabled"

# Проверка связи с relay
info "Проверка связи с relay ($RELAY_HOST)..."
sleep 2
if ping -c 2 -W 3 "$RELAY_HOST" >/dev/null 2>&1; then
    ok "Relay $RELAY_HOST доступен"
else
    warn "Relay НЕ доступен — добавь WG pubkey на relay и перезапусти WG там"
fi

# ─── 5. Worker keys + env ────────────────────────────────────────────
step "5/8" "Worker keys + env"

mkdir -p config

if [ ! -f "config/worker_keys.json" ]; then
    .venv/bin/python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
from shared.crypto import generate_keypair, save_keypair
from pathlib import Path
priv, pub = generate_keypair()
save_keypair(Path('config/worker_keys.json'), priv, pub)
print(f"Worker key: {pub.hex()[:32]}...")
PYEOF
fi
ok "worker_keys.json"

cat > "$ENV_FILE" <<EOF
export PASSWORD="$BOOTSTRAP_TOKEN"
export BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN"
export WG_ADDR="$WG_ADDR"
export P2P_PORT="9100"
EOF
chmod 600 "$ENV_FILE"
ok "Env: $ENV_FILE"

echo "$BOOTSTRAP_TOKEN" > "$SECRETS_DIR/bootstrap_token.txt"
chmod 600 "$SECRETS_DIR/bootstrap_token.txt"

# ─── 6. Проверка импортов ────────────────────────────────────────────
step "6/8" "Проверка импортов"

.venv/bin/python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
mods = [
    'shared.crypto', 'shared.protocol', 'shared.module_pack',
    'shared.ca', 'shared.directory', 'shared.bootstrap',
    'shared.discovery',
    'worker.agent', 'worker.p2p', 'worker.relay',
    'worker.loader', 'worker.executor',
]
for m in mods:
    try:
        __import__(m)
        print(f"  \033[1;32m✓\033[0m {m}")
    except Exception as e:
        print(f"  \033[1;31m✗\033[0m {m}: {e}")
        sys.exit(1)
PYEOF

# ─── 7. Systemd ──────────────────────────────────────────────────────
step "7/8" "Systemd service"

sudo tee /etc/systemd/system/livelist-worker.service > /dev/null <<EOF
[Unit]
Description=LiveList Worker
After=network-online.target wg-quick@${WG_IFACE}.service
Wants=network-online.target wg-quick@${WG_IFACE}.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/.venv/bin/python3 -m worker.agent \\
    --password \${PASSWORD} \\
    --bootstrap-token \${BOOTSTRAP_TOKEN} \\
    --wg-addr \${WG_ADDR} \\
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
ok "Systemd enabled"

# ─── 8. Итог ─────────────────────────────────────────────────────────
step "8/8" "Готово"

echo -e "${G}"
cat << EOF
╔══════════════════════════════════════════════════════════╗
║              WORKER READY                                ║
╠══════════════════════════════════════════════════════════╣
║  Install:    $INSTALL_DIR
║  WG:         $WG_IFACE ($WG_ADDR)
║  WG PUB:     $WG_PUB
║  Relay:      $RELAY_HOST
║  Master:     (auto-discovery по WG broadcast)
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${N}"

echo -e "${Y}"
cat << EOF
🚀 ЗАПУСК:

  sudo systemctl start livelist-worker
  journalctl -u livelist-worker -f

ЧТО ПРОИЗОЙДЁТ:
  1. VPS подключится к relay ($RELAY_HOST)
  2. Discovery listener слушает на 0.0.0.0:9051
  3. Master (kali) broadcast'ит свой WG-адрес каждые 10 сек
  4. VPS узнаёт master → 10.10.0.1:9050
  5. Enrollment через bootstrap token
  6. Получает сертификат + discovery_psk
  7. Регистрируется в directory

ФАЙЛЫ:
  $SECRETS_DIR/wg_worker_pub.txt  — WG public
  $SECRETS_DIR/bootstrap_token.txt — токен
  $INSTALL_DIR/config/certificate.json — выдастся master

ОТПРАВЬ НА RELAY ($RELAY_HOST) WG PUBKEY:
  $WG_PUB
EOF
echo -e "${N}"