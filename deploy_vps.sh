#!/bin/bash
# deploy_vps.sh — развёртывание воркера с автоматическим enrollment
#
# Задаёшь 4 переменные:
#   BOOTSTRAP_TOKEN     — из master> token
#   BOOTSTRAP_PASSWORD  — из master (config/bootstrap_password.txt)
#   MASTER_HOST         — real IP Kali
#   WG_ADDR             — 10.10.0.10 (10.10.0.11, ...)
#
# Всё остальное — автоматом.

set -e

GITHUB_URL="${GITHUB_URL:-https://github.com/NikLasNL/livelist-worker.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/livelist-worker}"
WG_IFACE="${WG_IFACE:-wg-mesh}"
WG_ADDR="${WG_ADDR:-}"
MASTER_HOST="${MASTER_HOST:-}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-}"
BOOTSTRAP_PASSWORD="${BOOTSTRAP_PASSWORD:-}"
SECRETS_DIR="${SECRETS_DIR:-$HOME/livelist-secrets}"
ENV_FILE="$HOME/.livelist_worker.env"

# ─── Цвета ────────────────────────────────────────────────────────
C='\033[1;36m'; Y='\033[1;33m'; G='\033[1;32m'; R='\033[1;31m'; N='\033[0m'
ok()    { echo -e "${G}  ✓ $*${N}"; }
fail()  { echo -e "${R}  ✗ $*${N}"; }
warn()  { echo -e "${Y}  ⚠ $*${N}"; }
info()  { echo -e "${C}  → $*${N}"; }
step()  { echo -e "\n${C}[$1/8] $2${N}"; }

# ─── BANNER ────────────────────────────────────────────────────────
echo -e "${C}"
cat << 'BANNER'
╔══════════════════════════════════════════════════════════╗
║   LiveList WORKER — auto enrollment + PSK rotation       ║
╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${N}"

# ─── Ввод ────────────────────────────────────────────────────────
if [ -z "$BOOTSTRAP_TOKEN" ]; then
    read -p "Bootstrap token (XXXX-XXXX-XXXX-XXXX-XXXX): " BOOTSTRAP_TOKEN
fi
if [ -z "$BOOTSTRAP_PASSWORD" ]; then
    read -sp "Bootstrap password (long hex): " BOOTSTRAP_PASSWORD
    echo
fi
if [ -z "$MASTER_HOST" ]; then
    read -p "Master public IP: " MASTER_HOST
fi
if [ -z "$WG_ADDR" ]; then
    read -p "WG addr (default 10.10.0.10): " WG_ADDR
    WG_ADDR="${WG_ADDR:-10.10.0.10}"
fi

echo
info "Setup:"
info "  Master:             $MASTER_HOST"
info "  WG addr:            $WG_ADDR"
info "  Bootstrap token:    ${BOOTSTRAP_TOKEN:0:8}..."
info "  Bootstrap password: ${BOOTSTRAP_PASSWORD:0:8}..."
echo

# ─── 1. Зависимости ──────────────────────────────────────────────
step "1" "Зависимости"

sudo apt update -qq
sudo apt install -y -qq \
    python3 python3-pip python3-venv \
    wireguard wireguard-tools \
    git curl jq iputils-ping 2>&1 | tail -2
ok "apt packages"

# ─── 2. Git clone ────────────────────────────────────────────────
step "2" "Git clone"

mkdir -p "$(dirname "$INSTALL_DIR")"
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR"
    git pull --quiet || true
    ok "Updated: $(git rev-parse --short HEAD 2>/dev/null || echo '?')"
else
    git clone --quiet "$GITHUB_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    ok "Cloned"
fi

# Проверка структуры
for f in shared/crypto.py shared/protocol.py shared/ca.py \
         shared/directory.py shared/bootstrap.py shared/discovery.py \
         shared/psk_auth.py \
         worker/agent.py worker/p2p.py worker/loader.py \
         worker/executor.py worker/relay.py worker/psk_listener.py; do
    if [ ! -f "$INSTALL_DIR/$f" ]; then
        fail "Missing: $f"
        exit 1
    fi
done
ok "Структура OK"

# ─── 3. Python venv ─────────────────────────────────────────────
step "3" "Python venv"

[ ! -d ".venv" ] && python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
ok "venv + requirements"

# ─── 4. WireGuard setup (пока без peer) ─────────────────────────
step "4" "WireGuard"

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

info "WG pub: $WG_PUB"

# Создаём placeholder WG conf — заполнится автоматом на enroll
sudo mkdir -p /etc/wireguard
if [ ! -f "/etc/wireguard/${WG_IFACE}.conf" ]; then
    sudo tee "/etc/wireguard/${WG_IFACE}.conf" > /dev/null <<EOF
[Interface]
PrivateKey = $WG_PRIV
Address = $WG_ADDR/24

# Peer заполнится автоматически после enrollment
EOF
    sudo chmod 600 "/etc/wireguard/${WG_IFACE}.conf"
fi
ok "WG конфиг создан"

# ─── 5. Sudoers для wg ──────────────────────────────────────────
step "5" "Sudoers для wg"

echo "$USER ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick, /usr/bin/ip" | \
    sudo tee /etc/sudoers.d/livelist-wg > /dev/null
sudo chmod 440 /etc/sudoers.d/livelist-wg
ok "Разрешены wg, wg-quick, ip без пароля"

# ─── 6. Env + systemd ───────────────────────────────────────────
step "6" "Env + systemd"

cat > "$ENV_FILE" <<EOF
export MASTER="$MASTER_HOST:9050"
export PASSWORD="$BOOTSTRAP_TOKEN"
export BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN"
export BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD"
export WG_ADDR="$WG_ADDR"
export P2P_PORT="9100"
export RELAY_PORT="9200"
EOF
chmod 600 "$ENV_FILE"
ok "Env: $ENV_FILE"

sudo tee /etc/systemd/system/livelist-worker.service > /dev/null <<EOF
[Unit]
Description=LiveList Worker
After=network-online.target
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
    --bootstrap-password \${BOOTSTRAP_PASSWORD} \\
    --wg-addr \${WG_ADDR} \\
    --p2p-port \${P2P_PORT} \\
    --relay-port \${RELAY_PORT}
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

# ─── 7. Проверка импортов ───────────────────────────────────────
step "7" "Проверка импортов"

cd "$INSTALL_DIR"
.venv/bin/python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
mods = [
    'shared.crypto', 'shared.protocol', 'shared.module_pack',
    'shared.ca', 'shared.directory', 'shared.bootstrap',
    'shared.discovery', 'shared.psk_auth',
    'worker.agent', 'worker.p2p', 'worker.relay',
    'worker.loader', 'worker.executor', 'worker.psk_listener',
]
for m in mods:
    try:
        __import__(m)
        print(f"  \033[1;32m✓\033[0m {m}")
    except Exception as e:
        print(f"  \033[1;31m✗\033[0m {m}: {e}")
        sys.exit(1)
PYEOF

# ─── 8. Итог ────────────────────────────────────────────────────
step "8" "Готово"

echo -e "${G}"
cat << EOF
╔══════════════════════════════════════════════════════════╗
║              WORKER READY                                ║
╠══════════════════════════════════════════════════════════╣
║  Install:           $INSTALL_DIR
║  WG:                $WG_IFACE ($WG_ADDR)
║  WG pub:            $WG_PUB
║  Master:            $MASTER_HOST:9050
║  PSK listener:      0.0.0.0:9052
║  Discovery listener:0.0.0.0:9051
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${N}"

echo -e "${Y}"
cat << 'EOF'
🚀 СЛЕДУЮЩИЕ ШАГИ:

1. Запусти воркер:
     sudo systemctl start livelist-worker
     journalctl -u livelist-worker -f

2. На Кали запусти master и сделай PSK handshake:
     cd ~/SEC/livelist-master
     source .venv/bin/activate
     python3 -c "
     import asyncio
     from master.psk_client import PSKClient
     from pathlib import Path
     pwd = Path('config/bootstrap_password.txt').read_text().strip()
     c = PSKClient(bootstrap_password=pwd)
     ok, pub = asyncio.run(c.hello('<VPS_IP>'))
     print('OK' if ok else 'FAIL', pub.hex() if pub else '')
     "

   После этого VPS получит новый пароль, старый bootstrap станет невалиден.

3. На Кали добавь WG peer:
     sudo wg set wg-mesh peer <WG_PUB> allowed-ips <WG_ADDR>/32
     ping <WG_ADDR>

4. Проверь в CLI мастера:
     master> workers

EOF
echo -e "${N}"