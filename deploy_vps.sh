#!/bin/bash
# deploy_vps.sh — упрощённый деплой (только bootstrap-token)
#
# Использование:
#   BOOTSTRAP_TOKEN=XXXX-XXXX-XXXX-XXXX-XXXX \
#   MASTER_HOST=5.6.7.8 \
#   ./deploy_vps.sh
#
# Или интерактивно: ./deploy_vps.sh

set -e

GITHUB_URL="${GITHUB_URL:-https://github.com/NikLasNL/livelist-worker.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/livelist-worker}"
WG_IFACE="${WG_IFACE:-wg-mesh}"
WG_ADDR="${WG_ADDR:-10.10.0.10}"
MASTER_HOST="${MASTER_HOST:-}"
WG_PORT="${WG_PORT:-51820}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-}"
SECRETS_DIR="${SECRETS_DIR:-$HOME/livelist-secrets}"
ENV_FILE="$HOME/.livelist_worker.env"

C='\033[1;36m'; Y='\033[1;33m'; G='\033[1;32m'; R='\033[1;31m'; N='\033[0m'
ok()    { echo -e "${G}  ✓ $*${N}"; }
fail()  { echo -e "${R}  ✗ $*${N}"; }
info()  { echo -e "${C}  → $*${N}"; }
warn()  { echo -e "${Y}  ⚠ $*${N}"; }
step()  { echo -e "\n${C}[$1] $2${N}"; }

echo -e "${C}"
cat << 'BANNER'
╔══════════════════════════════════════════════════════════╗
║   LiveList WORKER — auto-enrollment                     ║
╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${N}"

# Интерактивный ввод (только 2 поля!)
if [ -z "$MASTER_HOST" ]; then
    read -p "Master public IP: " MASTER_HOST
fi
if [ -z "$BOOTSTRAP_TOKEN" ]; then
    read -p "Bootstrap token (XXXX-XXXX-XXXX-XXXX-XXXX): " BOOTSTRAP_TOKEN
fi

# ─────────────────────────────────────────────────────────────────────
step "1/8" "Зависимости"
# ─────────────────────────────────────────────────────────────────────

sudo apt update -qq
sudo apt install -y -qq \
    python3 python3-pip python3-venv \
    wireguard wireguard-tools \
    git curl jq iputils-ping 2>&1 | tail -2
ok "apt packages"

# ─────────────────────────────────────────────────────────────────────
step "2/8" "Клонирование репо"
# ─────────────────────────────────────────────────────────────────────

mkdir -p "$(dirname "$INSTALL_DIR")"

if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR"
    git pull --quiet
    ok "Updated: $(git rev-parse --short HEAD)"
else
    git clone --quiet "$GITHUB_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    ok "Cloned"
fi

# ─────────────────────────────────────────────────────────────────────
step "3/8" "Python venv"
# ─────────────────────────────────────────────────────────────────────

[ ! -d ".venv" ] && python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
ok "venv + requirements"

# ─────────────────────────────────────────────────────────────────────
step "4/8" "WireGuard (клиент VPS-1)"
# ─────────────────────────────────────────────────────────────────────
# В новой архитектуре: VPS подключается к VPS-1 (bootstrap relay).
# VPS-1 подключается к Kali.
#
# Если это ПЕРВЫЙ VPS (bootstrap) — он сам подключается к Kali.
# Если это второй VPS — он подключается к VPS-1.

# Определяем — bootstrap это или leaf
MY_PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org || echo "")
info "My public IP: ${MY_PUBLIC_IP:-none}"

# Просим у пользователя bootstrap relay IP
# (для первого VPS = MASTER_HOST, для последующих = VPS-1 IP)
read -p "Connect to (bootstrap relay IP, default=$MASTER_HOST): " RELAY_HOST
RELAY_HOST="${RELAY_HOST:-$MASTER_HOST}"

# Свой WG-приватник (генерим при первом запуске)
WG_PRIV_PATH="$SECRETS_DIR/wg_worker_priv.txt"
mkdir -p "$SECRETS_DIR"

if [ ! -f "$WG_PRIV_PATH" ]; then
    wg genkey > "$WG_PRIV_PATH"
    chmod 600 "$WG_PRIV_PATH"
fi
WG_PRIV=$(cat "$WG_PRIV_PATH")
WG_PUB=$(echo "$WG_PRIV" | wg pubkey)

echo "$WG_PUB" > "$SECRETS_DIR/wg_worker_pub.txt"
chmod 600 "$SECRETS_DIR/wg_worker_pub.txt"

# Временный wg-mesh.conf — перезаписывается при enrollment
sudo mkdir -p /etc/wireguard
if [ ! -f "/etc/wireguard/${WG_IFACE}.conf" ]; then
    sudo tee "/etc/wireguard/${WG_IFACE}.conf" > /dev/null <<EOF
[Interface]
PrivateKey = $WG_PRIV
Address = $WG_ADDR/24

[Peer]
# Placeholder — заполнится после enrollment
PublicKey = 0000000000000000000000000000000000000000000=
Endpoint = ${RELAY_HOST}:${WG_PORT}
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
EOF
    sudo chmod 600 "/etc/wireguard/${WG_IFACE}.conf"
fi

info "WireGuard pubkey: $WG_PUB"
info "Save this for bootstrap-1 peer config if you are first VPS"

# ─────────────────────────────────────────────────────────────────────
step "5/8" "Bootstrap enrollment"
# ─────────────────────────────────────────────────────────────────────

mkdir -p config

# Генерируем worker keypair
if [ ! -f "config/worker_keys.json" ]; then
    .venv/bin/python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
from shared.crypto import generate_keypair, save_keypair
from pathlib import Path
priv, pub = generate_keypair()
save_keypair(Path('config/worker_keys.json'), priv, pub)
print(f"Worker keypair generated: {pub.hex()[:32]}...")
PYEOF
fi

# Сохраняем master info + токен
cat > "$ENV_FILE" <<EOF
export MASTER="$MASTER_HOST:9050"
export PASSWORD="$BOOTSTRAP_TOKEN"          # 2FA для handshake = токен
export BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN"
export WG_ADDR="$WG_ADDR"
export P2P_PORT="9100"
EOF
chmod 600 "$ENV_FILE"
ok "Env: $ENV_FILE"

echo "$BOOTSTRAP_TOKEN" > "$SECRETS_DIR/bootstrap_token.txt"
chmod 600 "$SECRETS_DIR/bootstrap_token.txt"

# ─────────────────────────────────────────────────────────────────────
step "6/8" "Проверка импортов"
# ─────────────────────────────────────────────────────────────────────

.venv/bin/python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
for mod in ['shared.crypto', 'shared.protocol', 'shared.ca',
            'shared.directory', 'shared.bootstrap',
            'shared.module_pack', 'worker.agent', 'worker.p2p',
            'worker.relay', 'worker.loader', 'worker.executor']:
    try:
        __import__(mod)
        print(f"  \033[1;32m✓\033[0m {mod}")
    except Exception as e:
        print(f"  \033[1;31m✗\033[0m {mod}: {e}")
        sys.exit(1)
PYEOF

# ─────────────────────────────────────────────────────────────────────
step "7/8" "First enrollment"
# ─────────────────────────────────────────────────────────────────────

info "Connecting to master to get certificate..."
source "$ENV_FILE"

# Первый запуск — enroll
timeout 30 .venv/bin/python3 -m worker.agent \
    --master "$MASTER_HOST:9050" \
    --password "$BOOTSTRAP_TOKEN" \
    --bootstrap-token "$BOOTSTRAP_TOKEN" \
    --wg-addr "$WG_ADDR" \
    --p2p-port 9100 \
    --enroll-only \
    || {
    warn "Enrollment failed or timed out"
    warn "Продолжаю — воркер enrol'ится при первом запуске systemd"
}

# Проверка что сертификат получен
if [ -f "config/certificate.json" ]; then
    ok "Certificate received"
    .venv/bin/python3 -c "
import json
c = json.load(open('config/certificate.json'))
print(f\"  WG addr: {c.get('wg_addr')}\")
print(f\"  Hostname: {c.get('hostname')}\")
print(f\"  can_relay: {c.get('can_relay')}\")
print(f\"  Public IP: {c.get('public_ip')}\")
"
fi

# ─────────────────────────────────────────────────────────────────────
step "8/8" "Systemd + финал"
# ─────────────────────────────────────────────────────────────────────

sudo tee /etc/systemd/system/livelist-worker.service > /dev/null <<EOF
[Unit]
Description=LiveList Worker
After=network-online.target wg-quick@${WG_IFACE}.service
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/.venv/bin/python3 -m worker.agent \\
    --master \${MASTER} \\
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
ok "Systemd: enabled"

echo -e "${G}"
cat << EOF
╔══════════════════════════════════════════════════════════╗
║              WORKER READY                                ║
╠══════════════════════════════════════════════════════════╣
║  Install:     $INSTALL_DIR
║  WG:          $WG_IFACE ($WG_ADDR)
║  WG PUB:      $WG_PUB
║  Cert:        $([ -f config/certificate.json ] && echo "✓ enrolled" || echo "✗ pending")
╚══════════════════════════════════════════════════════════╝

Запуск:
  sudo systemctl start livelist-worker
  journalctl -u livelist-worker -f
EOF
echo -e "${N}"