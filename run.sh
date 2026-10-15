#!/bin/bash
# run.sh — универсальный запуск

set -e
cd "$(dirname "$0")"

MODE="${1:-help}"
shift || true

case "$MODE" in
    master)
        python3 -m master.cli "$@"
        ;;
    master-nocli)
        python3 -m master.server --no-cli "$@"
        ;;
    worker)
        python3 -m worker.agent "$@"
        ;;
    webui)
        python3 -c "
import asyncio, sys
from master.server import MasterServer
from master.webui import run_webui
async def main():
    m = MasterServer()
    import asyncio
    asyncio.create_task(m.start())
    await asyncio.sleep(0.5)
    await run_webui(m)
asyncio.run(main())
" "$@"
        ;;
    show-master-key)
        python3 -c "
from master.server import MasterServer
m = MasterServer()
print(f'Master public key: {m.static_pub.hex()}')
"
        ;;
    show-worker-key)
        python3 -c "
from worker.agent import WorkerAgent
a = WorkerAgent('0.0.0.0:1', '00'*32)
print(f'Worker public key: {a.static_pub.hex()}')
"
        ;;
    *)
        echo "Usage: $0 {master|master-nocli|worker|webui|show-master-key|show-worker-key}"
        exit 1
        ;;
esac