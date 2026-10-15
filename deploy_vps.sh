#!/bin/bash
# deploy_vps.sh — полное развёртывание + проверка воркера LiveList
#
# Что делает:
#   0. Проверка окружения (OS, юзер, место)
#   1. Установка зависимостей (python, wireguard, git, curl, jq)
#   2. Git clone публичного репо (без ключей — публичный!)
#   3. Python venv + requirements
#   4. WireGuard setup (ключи + подъём + peer мастера)
#   5. LiveList worker keys
#   6. 2FA password + env
#   7. ПРОВЕРКА WireGuard (порт, IP, ping мастера)
#   8. ПРОВЕРКА структуры worker (нет модулей, кроме .gitkeep)
#   9. ПРОВЕРКА импортов всех модулей
#  10. DRY-RUN WorkerAgent
#  11. Проверка порта P2P
#  12. Сохранение worker-info.txt (для мастера)
#  13. Systemd service + финальная сводка
#
# Использование:
#   ./deploy_vps.sh
#   MASTER_HOST=1.2.3.4 MASTER_WG_PUBKEY=... ./deploy_vps.sh
#
# Переменные окружения (иначе спросит интерактивно):
#   GITHUB_URL          — публичный репо (default: placeholder)
#   MASTER_HOST         — публичный IP мастера
#   MASTER_PORT         — WG порт мастера (default 51820)
#   MASTER_WG_PUBKEY    — WG public мастера
#   MASTER_LIVELIST_KEY — LiveList public мастера (hex)
#   PASSWORD            — 2FA password
#   WG_ADDR             — WG адрес воркера (default 10.10.0.10)
#   P2P_PORT            — P2P порт воркера (default 9100)
#   INSTALL_DIR         — куда клонировать (default ~/livelist-worker)

set -e

# ═════════════════════════════════════════════════════════════════════
# ⚙️  НАСТРОЙКИ
# ═════════════════════════════════════════════════════════════════════

GITHUB_URL="${GITHUB_URL:-https://github.com/NikLasNL/livelist-worker.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/livelist-worker}"
WG_IFACE="${WG_IFACE:-wg-mesh}"
WG_ADDR="${WG_ADDR:-10.10.0.10}"
P2P_PORT="${P2P_PORT:-9100}"
MASTER_HOST="${MASTER_HOST:-}"
MASTER_PORT="${MASTER_PORT:-51820}"
MASTER_WG_PUBKEY="${MASTER_WG_PUBKEY:-}"
MASTER_LIVELIST_KEY="${MASTER_LIVELIST_KEY:-}"
PASSWORD="${PASSWORD:-${LIVELIST_PASSWORD:-}}"
SECRETS_DIR="${SECRETS_DIR:-$HOME/livelist-secrets}"
ENV_FILE="$HOME/.livelist_worker.env"

# ═════════════════════════════════════════════════════════════════════
# Цвета
# ═════════════════════════════════════════════════════════════════════

C='\033[1;36m'; Y='\033[1;33m'; G='\033[1;32m'; R='\033[1;31m'; N='\033[0m'
BG='\033[1;34m'

ok()    { echo -e "${G}  ✓ $*${N}"; }
fail()  { echo -e "${R}  ✗ $*${N}"; }
warn()  { echo -e "${Y}  ⚠ $*${N}"; }
info()  { echo -e "${C}  → $*${N}"; }
step()  { echo -e "\n${BG}[$1] $2${N}"; }

echo -e "${C}"
cat << 'BANNER'
╔══════════════════════════════════════════════════════════╗
║   LiveList WORKER — deployment + verification           ║
║   Debian / Ubuntu (VPS)                                  ║
╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${N}"

# ═════════════════════════════════════════════════════════════════════
# ИНТЕРАКТИВНЫЙ ВВОД
# ═════════════════════════════════════════════════════════════════════

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

# ═════════════════════════════════════════════════════════════════════
# 0. Проверка окружения
# ═════════════════════════════════════════════════════════════════════

step "0/13" "Проверка окружения"

if ! command -v apt >/dev/null 2>&1; then
    fail "Требуется Debian/Ubuntu"
    exit 1
fi
ok "apt найден"

if [ "$EUID" -eq 0 ]; then
    fail "Не запускай от root"
    exit 1
fi
ok "Пользователь: $USER"

AVAIL=$(df -BG "$HOME" | awk 'NR==2 {print $4}' | tr -d 'G')
if [ "$AVAIL" -lt 1 ]; then
    fail "Мало места: ${AVAIL}G"
    exit 1
fi
ok "Место: ${AVAIL}G"

ARCH=$(uname -m)
ok "Архитектура: $ARCH"

# ═════════════════════════════════════════════════════════════════════
# 1. Установка зависимостей
# ═════════════════════════════════════════════════════════════════════

step "1/13" "Установка зависимостей"

sudo apt update -qq
sudo apt install -y -qq \
    python3 python3-pip python3-venv \
    wireguard wireguard-tools \
    git curl jq iputils-ping 2>&1 | tail -2

for cmd in python3 git curl wg wg-quick jq ping; do
    if command -v "$cmd" >/dev/null; then
        ok "$cmd"
    else
        fail "$cmd не установлен"
        exit 1
    fi
done

# ═════════════════════════════════════════════════════════════════════
# 2. GIT CLONE публичного репо
# ═════════════════════════════════════════════════════════════════════

step "2/13" "Git clone публичного репо"

mkdir -p "$(dirname "$INSTALL_DIR")"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Обновляю существующий репо"
    cd "$INSTALL_DIR"
    git fetch --quiet origin 2>/dev/null || true
    LOCAL=$(git rev-parse HEAD 2>/dev/null || echo "")
    REMOTE=$(git rev-parse @{u} 2>/dev/null || echo "")
    if [ -n "$LOCAL" ] && [ -n "$REMOTE" ] && [ "$LOCAL" != "$REMOTE" ]; then
        info "Есть обновления, pull..."
        git pull --quiet
        ok "Обновлено до $(git rev-parse --short HEAD)"
    else
        ok "Уже актуален: $(git rev-parse --short HEAD 2>/dev/null)"
    fi
elif [ -d "$INSTALL_DIR" ]; then
    warn "$INSTALL_DIR существует, но это не git-репо"
    info "Продолжаю с существующими файлами"
    cd "$INSTALL_DIR"
else
    info "Клонирую: $GITHUB_URL"
    if ! git clone --quiet "$GITHUB_URL" "$INSTALL_DIR" 2>&1; then
        fail "git clone провалился"
        echo
        echo -e "${Y}Возможные причины:${N}"
        echo "  • Репозиторий приватный (нужен SSH-ключ или PAT)"
        echo "  • Неверный URL: $GITHUB_URL"
        echo "  • Нет интернета"
        echo
        exit 1
    fi
    cd "$INSTALL_DIR"
    ok "Клонирован в $INSTALL_DIR"
fi

# Проверка что репо публичный (не требует авторизации)
if [ -d ".git" ]; then
    REMOTE_URL=$(git config --get remote.origin.url 2>/dev/null || echo "")
    if echo "$REMOTE_URL" | grep -qE "^https://"; then
        ok "Remote: $REMOTE_URL"
    else
        info "Remote: $REMOTE_URL"
    fi
fi

# Проверка структуры
REQUIRED_FILES=(
    "shared/__init__.py"
    "shared/crypto.py"
    "shared/protocol.py"
    "shared/module_pack.py"
    "worker/__init__.py"
    "worker/agent.py"
    "worker/p2p.py"
    "worker/loader.py"
    "worker/executor.py"
    "cve_explore.py"
    "common.py"
    "requirements.txt"
)

MISSING=()
for f in "${REQUIRED_FILES[@]}"; do
    if [ -f "$INSTALL_DIR/$f" ]; then
        ok "$f"
    else
        fail "$f — ОТСУТСТВУЕТ"
        MISSING+=("$f")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo
    fail "Не хватает ${#MISSING[@]} файлов в репо. Проверь GitHub."
    exit 1
fi

# ═════════════════════════════════════════════════════════════════════
# 3. Python venv + requirements
# ═════════════════════════════════════════════════════════════════════

step "3/13" "Python venv"

cd "$INSTALL_DIR"

if [ ! -d ".venv" ]; then
    info "Создаю .venv"
    python3 -m venv .venv
fi
ok ".venv готов"

.venv/bin/pip install --quiet --upgrade pip
info "Устанавливаю requirements..."
.venv/bin/pip install --quiet -r requirements.txt
ok "Requirements установлены"

.venv/bin/python3 << 'PYEOF'
import sys
mods = ['nacl', 'aiohttp']
for m in mods:
    try:
        __import__(m)
        print(f"  ✓ {m}")
    except ImportError:
        print(f"  ✗ {m}")
        sys.exit(1)
PYEOF

# ═════════════════════════════════════════════════════════════════════
# 4. WireGuard setup
# ═════════════════════════════════════════════════════════════════════

step "4/13" "WireGuard setup"

WG_CONF="/etc/wireguard/${WG_IFACE}.conf"

if [ ! -f "$WG_CONF" ]; then
    info "Генерирую WG ключи воркера"
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
    ok "Создан $WG_CONF"
else
    info "Использую существующий $WG_CONF"
    WG_PRIV=$(sudo grep PrivateKey "$WG_CONF" | awk '{print $3}')
    WG_PUB=$(echo "$WG_PRIV" | wg pubkey)
fi

mkdir -p "$SECRETS_DIR"
echo "$WG_PUB" > "$SECRETS_DIR/wg_worker_pub.txt"
echo "$WG_PRIV" > "$SECRETS_DIR/wg_worker_priv.txt"
chmod 600 "$SECRETS_DIR"/*.txt
ok "WG ключи → $SECRETS_DIR"

if ! ip link show "$WG_IFACE" &>/dev/null; then
    info "Поднимаю $WG_IFACE"
    sudo wg-quick up "$WG_IFACE"
fi
ok "$WG_IFACE поднят"

sudo systemctl enable "wg-quick@${WG_IFACE}" 2>/dev/null || true
ok "Автозапуск включён"

# ═════════════════════════════════════════════════════════════════════
# 5. LiveList worker keys
# ═════════════════════════════════════════════════════════════════════

step "5/13" "LiveList worker keys"

cd "$INSTALL_DIR"
mkdir -p config

if [ ! -f "config/worker_keys.json" ]; then
    info "Генерирую LiveList ключи воркера"
    .venv/bin/python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')
from shared.crypto import generate_keypair, save_keypair
from pathlib import Path
priv, pub = generate_keypair()
save_keypair(Path('config/worker_keys.json'), priv, pub)
print(f"  Public: {pub.hex()}")
PYEOF
fi

WORKER_LL_PUB=$(.venv/bin/python3 -c "
import sys; sys.path.insert(0, '.')
from shared.crypto import load_keypair
from pathlib import Path
_, pub = load_keypair(Path('config/worker_keys.json'))
print(pub.hex())
")

echo "$WORKER_LL_PUB" > "$SECRETS_DIR/worker_livelist_pub.txt"
chmod 600 "$SECRETS_DIR/worker_livelist_pub.txt"
ok "Worker LiveList public: ${WORKER_LL_PUB:0:32}..."

# Сохранить master pubkey для переподключений
echo "$MASTER_LIVELIST_KEY" > config/master_pubkey.txt
chmod 600 config/master_pubkey.txt
ok "Master pubkey сохранён в config/master_pubkey.txt"

# ═════════════════════════════════════════════════════════════════════
# 6. 2FA password + env
# ═════════════════════════════════════════════════════════════════════

step "6/13" "2FA password + env"

cat > "$ENV_FILE" <<EOF
export MASTER="$MASTER_HOST:9050"
export MASTER_KEY="$MASTER_LIVELIST_KEY"
export PASSWORD="$PASSWORD"
export WG_ADDR="$WG_ADDR"
export P2P_PORT="$P2P_PORT"
export MASTER_HOST="$MASTER_HOST"
export MASTER_PORT="$MASTER_PORT"
export MASTER_WG_PUBKEY="$MASTER_WG_PUBKEY"
EOF
chmod 600 "$ENV_FILE"
ok "Env сохранён: $ENV_FILE"

echo "$PASSWORD" > "$SECRETS_DIR/password.txt"
chmod 600 "$SECRETS_DIR/password.txt"
ok "Password: ${PASSWORD:0:8}..."

# ═════════════════════════════════════════════════════════════════════
# 7. ПРОВЕРКА WireGuard (порт, IP, ping мастера)
# ═════════════════════════════════════════════════════════════════════

step "7/13" "ПРОВЕРКА WireGuard"

echo -e "${C}  --- wg show ---${N}"
sudo wg show "$WG_IFACE" || { fail "wg show failed"; exit 1; }

echo -e "${C}  --- IP интерфейса ---${N}"
WG_IP=$(ip -4 addr show "$WG_IFACE" | grep -oP 'inet \K[\d.]+')
if [ "$WG_IP" = "$WG_ADDR" ]; then
    ok "IP: $WG_IP"
else
    fail "Ожидался $WG_ADDR, получен $WG_IP"
fi

echo -e "${C}  --- Handshake с мастером ---${N}"
sleep 3
HANDSHAKE=$(sudo wg show "$WG_IFACE" latest-handshakes | awk '{print $2}')
if [ -n "$HANDSHAKE" ] && [ "$HANDSHAKE" != "0" ]; then
    ok "Handshake прошёл"
else
    warn "Handshake ещё не прошёл (мастер может быть оффлайн)"
    warn "Проверь на мастере: добавлен ли WG pubkey"
fi

echo -e "${C}  --- Ping мастера 10.10.0.1 ---${N}"
if ping -c 2 -W 3 10.10.0.1 >/dev/null 2>&1; then
    ok "Мастер доступен: 10.10.0.1"
else
    fail "Мастер НЕ доступен (10.10.0.1)"
    echo
    echo -e "${Y}Проверь на мастере:${N}"
    echo "  1. sudo nano /etc/wireguard/${WG_IFACE}.conf"
    echo "  2. Добавь:"
    echo "     [Peer]"
    echo "     PublicKey = $WG_PUB"
    echo "     AllowedIPs = $WG_ADDR/32"
    echo "  3. sudo wg-quick down $WG_IFACE && sudo wg-quick up $WG_IFACE"
fi

echo -e "${C}  --- Firewall ---${N}"
if command -v ufw >/dev/null; then
    if sudo ufw status | head -1 | grep -q "active"; then
        warn "UFW активен — открываю $P2P_PORT/tcp"
        sudo ufw allow "$P2P_PORT/tcp" >/dev/null 2>&1 || true
        ok "UFW: разрешён $P2P_PORT/tcp"
    else
        ok "UFW неактивен"
    fi
fi

# ═════════════════════════════════════════════════════════════════════
# 8. ПРОВЕРКА структуры worker
# ═════════════════════════════════════════════════════════════════════

step "8/13" "ПРОВЕРКА структуры worker"

# worker_modules должна быть ПУСТА (кроме .gitkeep)
mkdir -p worker_modules
if [ ! -f "worker_modules/.gitkeep" ]; then
    touch worker_modules/.gitkeep
fi

MOD_FILES=$(find worker_modules -name "*.py" -not -name "_*" 2>/dev/null | wc -l)
if [ "$MOD_FILES" -eq 0 ]; then
    ok "worker_modules/ пуста (модули придут от мастера)"
else
    warn "worker_modules/ содержит $MOD_FILES .py файлов"
    info "Это нормально после первого подключения"
fi

# Проверка что нет лишних файлов в корне
if [ -f "master_keys.json" ]; then
    fail "Обнаружен master_keys.json в корне воркера!"
    exit 1
fi
ok "Нет master_keys.json (это worker)"

# config/
mkdir -p config
ok "config/ готов"

# Права на worker_keys
if [ -f "config/worker_keys.json" ]; then
    PERMS=$(stat -c '%a' config/worker_keys.json)
    if [ "$PERMS" = "600" ]; then
        ok "Права worker_keys.json: 600"
    else
        warn "Права $PERMS → ставлю 600"
        chmod 600 config/worker_keys.json
    fi
fi

# ═════════════════════════════════════════════════════════════════════
# 9. ПРОВЕРКА импортов
# ═════════════════════════════════════════════════════════════════════

step "9/13" "ПРОВЕРКА импортов"

.venv/bin/python3 << 'PYEOF'
import sys
sys.path.insert(0, '.')

modules = [
    ('shared.crypto',      ['Handshake', 'generate_keypair', 'load_keypair']),
    ('shared.protocol',    ['MsgType', 'read_message', 'write_message']),
    ('shared.module_pack', ['pack_module', 'unpack_module', 'derive_xor_key']),
    ('worker.agent',       ['WorkerAgent']),
    ('worker.p2p',         ['P2PNode']),
    ('worker.loader',      ['ModuleLoader']),
    ('worker.executor',    ['TaskExecutor']),
    ('cve_explore',        ['init_db', 'LIVELIST_DB']),
    ('common',             ['VPNGuardClient', 'TelegramNotifier']),
]

all_ok = True
for mod, attrs in modules:
    try:
        m = __import__(mod, fromlist=attrs)
        for a in attrs:
            if not hasattr(m, a):
                raise AttributeError(f"{mod}.{a} не найден")
        print(f"  \033[1;32m✓\033[0m {mod}")
    except Exception as e:
        print(f"  \033[1;31m✗\033[0m {mod}: {e}")
        all_ok = False

sys.exit(0 if all_ok else 1)
PYEOF

if [ $? -ne 0 ]; then
    fail "Проблемы с импортами"
    exit 1
fi

# ═════════════════════════════════════════════════════════════════════
# 10. DRY-RUN WorkerAgent
# ═════════════════════════════════════════════════════════════════════

step "10/13" "DRY-RUN WorkerAgent"

.venv/bin/python3 << 'PYEOF'
import sys, os, asyncio
sys.path.insert(0, '.')

from worker.agent import WorkerAgent

async def test():
    a = WorkerAgent(
        master_addr=os.environ.get('MASTER', '10.10.0.1:9050'),
        master_pubkey_hex=os.environ.get('MASTER_KEY', '00' * 32),
        wg_addr=os.environ.get('WG_ADDR', '10.10.0.10'),
        password=os.environ.get('PASSWORD', 'x'),
        p2p_port=int(os.environ.get('P2P_PORT', '9100')),
    )
    print(f"  \033[1;32m✓\033[0m WorkerAgent создан")
    print(f"    Master:    {a.master_addr}")
    print(f"    WG addr:   {a.wg_addr}")
    print(f"    P2P port:  {a.p2p_port}")
    print(f"    Password:  {'✓ set' if a.password else '✗'}")
    print(f"    Pubkey:    {a.static_pub.hex()[:32]}...")
    print(f"    Modules:   {a.loader.list_modules() or '(none)'}")

asyncio.run(test())
PYEOF

# ═════════════════════════════════════════════════════════════════════
# 11. Проверка порта P2P + система
# ═════════════════════════════════════════════════════════════════════

step "11/13" "Проверка порта P2P"

if sudo ss -tlnp 2>/dev/null | grep -q ":$P2P_PORT"; then
    ok "Порт $P2P_PORT уже слушается"
else
    info "Порт $P2P_PORT свободен (воркер не запущен)"
fi

# Проверка сервиса
if systemctl list-unit-files 2>/dev/null | grep -q "^livelist-worker.service"; then
    STATUS=$(systemctl is-active livelist-worker 2>/dev/null || echo "inactive")
    info "Сервис livelist-worker: $STATUS"
fi

# Проверка systemd unit
if [ -f "/etc/systemd/system/livelist-worker.service" ]; then
    ok "Systemd unit уже установлен"
fi

# ═════════════════════════════════════════════════════════════════════
# 12. Сохранение worker-info.txt
# ═════════════════════════════════════════════════════════════════════

step "12/13" "Сохранение worker-info"

WORKER_INFO="$SECRETS_DIR/worker-info.txt"
cat > "$WORKER_INFO" <<EOF
╔══════════════════════════════════════════════════════════╗
║  LiveList WORKER INFO                                    ║
║  Сгенерировано: $(date)                                 ║
╚══════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════
ОТПРАВЬ МАСТЕРУ:
═══════════════════════════════════════════════════════════

1. WireGuard peer (в /etc/wireguard/wg-mesh.conf на мастере):

    [Peer]
    PublicKey = $WG_PUB
    AllowedIPs = $WG_ADDR/32

2. LiveList whitelist (config/workers.json на мастере):

    "allowed": [
        "$WORKER_LL_PUB"
    ]

═══════════════════════════════════════════════════════════
КОНФИГУРАЦИЯ ВОРКЕРА:
═══════════════════════════════════════════════════════════

WORKER WG PUBLIC:      $WG_PUB
WORKER WG PRIVATE:     (в $SECRETS_DIR/wg_worker_priv.txt)
WORKER LIVELIST PUB:   $WORKER_LL_PUB
WORKER WG ADDR:        $WG_ADDR
WORKER P2P PORT:       $P2P_PORT

MASTER HOST:           $MASTER_HOST:$MASTER_PORT
MASTER LIVELIST KEY:   $MASTER_LIVELIST_KEY

═══════════════════════════════════════════════════════════
УПРАВЛЕНИЕ:
═══════════════════════════════════════════════════════════

Запуск сервиса:      sudo systemctl start livelist-worker
Статус:              sudo systemctl status livelist-worker
Логи:                journalctl -u livelist-worker -f
Остановка:           sudo systemctl stop livelist-worker

Ручной запуск:
  source $ENV_FILE
  cd $INSTALL_DIR
  ./.venv/bin/python3 -m worker.agent \\
      --master "$MASTER_HOST:9050" \\
      --master-key "$MASTER_LIVELIST_KEY" \\
      --password "$PASSWORD" \\
      --wg-addr "$WG_ADDR" \\
      --p2p-port "$P2P_PORT"

═══════════════════════════════════════════════════════════
Файлы секретов в $SECRETS_DIR:
═══════════════════════════════════════════════════════════
- wg_worker_pub.txt          — WG public воркера
- wg_worker_priv.txt         — WG private (СЕКРЕТ)
- worker_livelist_pub.txt    — LiveList public воркера
- password.txt               — 2FA password
- worker-info.txt            — этот файл
EOF

chmod 600 "$WORKER_INFO"
ok "worker-info.txt сохранён"

# ═════════════════════════════════════════════════════════════════════
# 13. Systemd service + финальная сводка
# ═════════════════════════════════════════════════════════════════════

step "13/13" "Systemd service + сводка"

# Создать systemd unit
sudo tee /etc/systemd/system/livelist-worker.service > /dev/null <<EOF
[Unit]
Description=LiveList Worker
After=network-online.target wg-quick@${WG_IFACE}.service
Wants=network-online.target wg-quick@${WG_IFACE}.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
Environment="MASTER=$MASTER_HOST:9050"
Environment="MASTER_KEY=$MASTER_LIVELIST_KEY"
Environment="PASSWORD=$PASSWORD"
Environment="WG_ADDR=$WG_ADDR"
Environment="P2P_PORT=$P2P_PORT"
ExecStart=$INSTALL_DIR/.venv/bin/python3 -m worker.agent \\
    --master \${MASTER} \\
    --master-key \${MASTER_KEY} \\
    --password \${PASSWORD} \\
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
ok "Systemd service установлен и включён"

# Финальная сводка
echo -e "${G}"
cat << EOF
╔══════════════════════════════════════════════════════════╗
║              WORKER READY                                ║
╠══════════════════════════════════════════════════════════╣
║  Install:      $INSTALL_DIR
║  WG:           $WG_IFACE ($WG_ADDR)
║  P2P port:     $P2P_PORT
║
║  WORKER WG PUB:      $WG_PUB
║  WORKER LIVELIST:    $WORKER_LL_PUB
║
║  Master:       $MASTER_HOST:$MASTER_PORT
║  Modules:      (пусто — придут от мастера)
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${N}"

echo -e "${Y}"
cat << EOF
🚀 СЛЕДУЮЩИЕ ШАГИ:

1. ⚠️  ОТПРАВЬ МАСТЕРУ (см. $WORKER_INFO):

   WG PUBLIC:      $WG_PUB
   LIVELIST PUB:   $WORKER_LL_PUB

   Мастер должен добавить:
   • WG peer в /etc/wireguard/${WG_IFACE}.conf
   • whitelist в config/workers.json

2. НА МАСТЕРЕ после добавления:
   sudo wg-quick down $WG_IFACE && sudo wg-quick up $WG_IFACE

3. ЗДЕСЬ запустить сервис:
   sudo systemctl start livelist-worker
   journalctl -u livelist-worker -f

4. Проверить подключение:
   ping 10.10.0.1
   sudo wg show

5. Ручной запуск (для отладки):
   source $ENV_FILE
   cd $INSTALL_DIR
   ./.venv/bin/python3 -m worker.agent \\
       --master "$MASTER_HOST:9050" \\
       --master-key "$MASTER_LIVELIST_KEY" \\
       --password "$PASSWORD" \\
       --wg-addr "$WG_ADDR" \\
       --p2p-port "$P2P_PORT"

ФАЙЛЫ СЕКРЕТОВ в $SECRETS_DIR:
  wg_worker_pub.txt
  wg_worker_priv.txt
  worker_livelist_pub.txt
  password.txt
  worker-info.txt
EOF
echo -e "${N}"