"""
worker/agent.py — автономный воркер v4
+ P2P full
+ Key rotation
+ Bootstrap key support
"""

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.crypto import (
    load_keypair, save_keypair, generate_keypair, Handshake,
    rotate_keypair,
)
from shared.protocol import (
    MsgType, read_message, write_message,
    send_big_file, FileReceiver, CHUNK_SIZE,
)

from worker.loader import ModuleLoader
from worker.executor import TaskExecutor
from worker.p2p import P2PNode


BASE = Path(__file__).parent.parent
CONFIG = BASE / "config"
CONFIG.mkdir(exist_ok=True)
MODULES_DIR = BASE / "worker_modules"
MODULES_DIR.mkdir(exist_ok=True)
LOGS_DIR = BASE / "logs"
LOGS_DIR.mkdir(exist_ok=True)
TASKS_CACHE = BASE / "task_results"
TASKS_CACHE.mkdir(exist_ok=True)
KEYS_BACKUP = CONFIG / "keys_backup"


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "worker.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("worker")


class WorkerAgent:
    def __init__(self, master_addr, master_pubkey_hex,
                 wg_addr="?", password=None, p2p_port=9100,
                 bootstrap_pubkey_hex=None):
        self.master_addr = master_addr
        self.master_pubkey = bytes.fromhex(master_pubkey_hex)
        self.wg_addr = wg_addr
        self.password = (password or os.environ.get("LIVELIST_PASSWORD")
                          or "changeme-please")
        self.p2p_port = p2p_port

        # Bootstrap key (опционально)
        self.bootstrap_pubkey = (bytes.fromhex(bootstrap_pubkey_hex)
                                  if bootstrap_pubkey_hex else None)

        # Keys
        self.key_path = CONFIG / "worker_keys.json"
        if not self.key_path.exists():
            priv, pub = generate_keypair()
            save_keypair(self.key_path, priv, pub)
            log.info(f"New worker key: {pub.hex()}")

        self.static_priv, self.static_pub = load_keypair(self.key_path)
        self.loader = ModuleLoader(MODULES_DIR)
        self.executor = TaskExecutor(self.loader)

        # P2P
        self.p2p = P2PNode(
            my_priv=self.static_priv,
            my_pub=self.static_pub,
            password=self.password,
            listen_port=self.p2p_port,
            on_data=self._on_p2p_data,
        )

        self.running = True
        self.reconnect_delay = 5
        self.max_reconnect_delay = 300

    # ═════════════════════════════════════════════════════════════════
    # Main loop
    # ═════════════════════════════════════════════════════════════════

    async def run(self):
        log.info("═" * 60)
        log.info(f"Worker v4 | pub={self.static_pub.hex()[:16]}")
        log.info(f"Master: {self.master_addr}")
        log.info(f"WG: {self.wg_addr}  P2P: {self.p2p_port}")
        log.info(f"Bootstrap: {'ON' if self.bootstrap_pubkey else 'OFF'}")
        log.info(f"Modules: {self.loader.list_modules()}")
        log.info("═" * 60)

        # Start P2P server
        try:
            await self.p2p.start_server()
        except Exception as e:
            log.warning(f"P2P server: {e}")

        while self.running:
            try:
                await self._run_session()
            except ConnectionRefusedError:
                log.warning(f"Master refused, retry {self.reconnect_delay}s")
            except asyncio.TimeoutError:
                log.warning(f"Timeout, retry {self.reconnect_delay}s")
            except Exception as e:
                log.error(f"Session: {e}", exc_info=True)

            await asyncio.sleep(self.reconnect_delay)
            self.reconnect_delay = min(
                self.reconnect_delay * 2, self.max_reconnect_delay
            )

        await self.p2p.stop()
        log.info("Stopped")

    async def _run_session(self):
        host, port = self.master_addr.rsplit(":", 1)
        port = int(port)

        log.info(f"Connecting to {host}:{port}...")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=15,
        )

        channel = await asyncio.wait_for(
            Handshake.client_handshake(
                reader, writer,
                my_static_priv=self.static_priv,
                server_static_pub=self.master_pubkey,
                password=self.password,
            ),
            timeout=20,
        )
        log.info("Handshake OK")
        self.reconnect_delay = 5

        # Регистрация
        await write_message(writer, channel, MsgType.STATUS, {
            "state": "online",
            "wg_addr": self.wg_addr,
            "p2p_port": self.p2p_port,
            "modules": self.loader.list_modules(),
            "version": "4.0",
            "started_at": int(time.time()),
        })

        if not self.loader.list_modules():
            await write_message(writer, channel, MsgType.REQUEST_MODULES)

        await self._flush_cached_results(writer, channel)
        await self._loop(reader, writer, channel)

    async def _flush_cached_results(self, writer, channel):
        pending = list(TASKS_CACHE.glob("*.json"))
        if not pending:
            return
        log.info(f"Flushing {len(pending)} cached results")
        for f in pending:
            try:
                data = f.read_bytes()
                await write_message(writer, channel,
                                     MsgType.TASK_RESULT, {
                    "task_id": f.stem, "task": "cached",
                }, body=data)
                f.unlink()
            except Exception as e:
                log.error(f"Flush {f.name}: {e}")

    # ═════════════════════════════════════════════════════════════════
    # Message loop
    # ═════════════════════════════════════════════════════════════════

    async def _loop(self, reader, writer, channel):
        receivers = {}

        while True:
            msg_type, header, body = await read_message(reader, channel)

            if msg_type == MsgType.PING:
                await write_message(writer, channel, MsgType.PONG)

            elif msg_type == MsgType.PUSH_MODULE:
                await self._handle_module(writer, channel, header, body)

            elif msg_type == MsgType.MODULE_CHUNK_START:
                fn = header["filename"]
                receivers[fn] = FileReceiver(MODULES_DIR / fn)
                receivers[fn].start(header)

            elif msg_type == MsgType.MODULE_CHUNK_CHUNK:
                fn = header["filename"]
                if fn in receivers:
                    receivers[fn].chunk(header, body)

            elif msg_type == MsgType.MODULE_CHUNK_DONE:
                fn = header["filename"]
                if fn in receivers:
                    size = receivers[fn].finish(header)
                    del receivers[fn]
                    await self._module_loaded(writer, channel, fn, size)

            elif msg_type == MsgType.PUSH_VPN:
                await self._handle_vpn(writer, channel, header, body)

            elif msg_type == MsgType.PUSH_UA:
                (BASE / "ua_json.json").write_bytes(body)
                log.info(f"UA updated")

            elif msg_type == MsgType.RUN_TASK:
                asyncio.create_task(
                    self._handle_task(writer, channel, header, body)
                )

            elif msg_type == MsgType.RELOAD:
                self.loader.reload_all()
                await write_message(writer, channel, MsgType.MODULE_ACK, {
                    "module": "*", "state": "reloaded",
                })

            # ═══ P2P ═══
            elif msg_type == MsgType.P2P_CONNECT:
                asyncio.create_task(
                    self._handle_p2p_connect(header)
                )

            # ═══ KEY ROTATION ═══
            elif msg_type == MsgType.KEY_ROTATE_REQUEST:
                await self._handle_key_rotate_request(writer, channel)

            elif msg_type == MsgType.KEY_ROTATE_ACK:
                await self._handle_key_rotate_ack(writer, channel, header)

            elif msg_type == MsgType.SHUTDOWN:
                log.warning("Shutdown from master")
                self.running = False
                return

    # ═════════════════════════════════════════════════════════════════
    # P2P handler
    # ═════════════════════════════════════════════════════════════════

    async def _handle_p2p_connect(self, header):
        peer_pub = header.get("peer_pub")
        peer_host = header.get("peer_host")
        peer_port = header.get("peer_port")
        role = header.get("role", "listener")

        log.info(f"[P2P] command: {role} → {peer_pub[:16]} "
                  f"@ {peer_host}:{peer_port}")

        if role == "initiator":
            if peer_host in ("?", "", None):
                log.warning("[P2P] initiator without host — skip")
                return
            # Небольшая задержка, чтобы listener уже был готов
            await asyncio.sleep(2)
            await self.p2p.connect_to_peer(peer_host, peer_port, peer_pub)
        else:
            # Listener — просто добавляем в allowed, ждём подключения
            try:
                self.p2p.allowed_peers.add(bytes.fromhex(peer_pub))
            except Exception:
                pass
            log.info(f"[P2P] awaiting incoming from {peer_pub[:16]}")

    async def _on_p2p_data(self, peer_pub_hex, msg_type, header, body):
        """Callback для входящих P2P сообщений."""
        log.info(f"[P2P] data from {peer_pub_hex[:16]}: {msg_type}")
        if msg_type == MsgType.P2P_DATA:
            payload = body.decode(errors="replace")
            log.info(f"[P2P] payload ({len(payload)} bytes): "
                      f"{payload[:100]}")

    # ═════════════════════════════════════════════════════════════════
    # Key rotation
    # ═════════════════════════════════════════════════════════════════

    async def _handle_key_rotate_request(self, writer, channel):
        log.info("[KEY] rotate requested — generating new keypair")
        old_priv, old_pub, new_priv, new_pub = rotate_keypair(
            self.key_path, KEYS_BACKUP
        )
        # Обновляем в памяти
        self.static_priv = new_priv
        self.static_pub = new_pub

        # Обновляем P2P (использует те же ключи)
        self.p2p.my_priv = new_priv
        self.p2p.my_pub = new_pub

        # Отправляем мастеру новый pubkey
        await write_message(writer, channel, MsgType.KEY_ROTATE_NEW, {
            "new_pub": new_pub.hex(),
            "old_pub": old_pub.hex(),
        })
        log.info(f"[KEY] sent new pubkey: {new_pub.hex()[:16]}")

    async def _handle_key_rotate_ack(self, writer, channel, header):
        new_master_pub_hex = header.get("new_pub")
        if new_master_pub_hex:
            self.master_pubkey = bytes.fromhex(new_master_pub_hex)
            log.info(f"[KEY] master rotated to "
                      f"{new_master_pub_hex[:16]}")

            # Сохраняем для будущих соединений
            master_key_file = CONFIG / "master_pubkey.txt"
            master_key_file.write_text(new_master_pub_hex)

        # Подтверждаем
        await write_message(writer, channel, MsgType.KEY_ROTATE_DONE, {
            "state": "acknowledged",
        })
        log.info("[KEY] rotation confirmed")

    # ═════════════════════════════════════════════════════════════════
    # Other handlers
    # ═════════════════════════════════════════════════════════════════

    async def _handle_module(self, writer, channel, header, body):
        name = header["module"]
        filename = header.get("filename", f"{name}.py")
        (MODULES_DIR / filename).write_bytes(body)
        await self._module_loaded(writer, channel, filename, len(body))

    async def _module_loaded(self, writer, channel, filename, size):
        name = filename.replace(".py", "")
        try:
            self.loader.load_module(name)
            await write_message(writer, channel, MsgType.MODULE_ACK, {
                "module": name, "state": "loaded",
            })
            log.info(f"Module loaded: {name} ({size} bytes)")
        except Exception as e:
            await write_message(writer, channel, MsgType.MODULE_ACK, {
                "module": name, "state": "error", "error": str(e),
            })

    async def _handle_vpn(self, writer, channel, header, body):
        filename = header.get("filename", "wg-new.conf")
        tmp = Path.home() / f".{filename}"
        tmp.write_bytes(body)
        tmp.chmod(0o600)
        try:
            import subprocess
            subprocess.run(["sudo", "cp", str(tmp),
                             f"/etc/wireguard/{filename}"],
                            check=True, timeout=10)
            subprocess.run(["sudo", "chmod", "600",
                             f"/etc/wireguard/{filename}"],
                            check=True, timeout=10)
            log.info(f"VPN installed: {filename}")
        except Exception as e:
            log.error(f"VPN install: {e}")

    async def _handle_task(self, writer, channel, header, body):
        task_id = header["task_id"]
        task_name = header["task"]
        params = header.get("params", {})
        log.info(f"Task {task_id}: {task_name}")

        try:
            result = await self.executor.run(task_name, params)
            result_bytes = json.dumps(result, ensure_ascii=False).encode()

            if len(result_bytes) < CHUNK_SIZE:
                await write_message(writer, channel,
                                     MsgType.TASK_RESULT, {
                    "task_id": task_id, "task": task_name,
                }, body=result_bytes)
            else:
                await send_big_file(
                    writer, channel, "task_result_chunk",
                    f"{task_id}.json", result_bytes,
                    extra={"task_id": task_id, "task": task_name},
                )

            (TASKS_CACHE / f"{task_id}.json").write_bytes(result_bytes)
            log.info(f"Task {task_id} done")

        except Exception as e:
            log.error(f"Task {task_id}: {e}", exc_info=True)
            await write_message(writer, channel, MsgType.TASK_ERROR, {
                "task_id": task_id, "task": task_name,
                "error": str(e),
            })


# ═════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════

async def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--master", required=True)
    p.add_argument("--master-key", required=True)
    p.add_argument("--password", default=None)
    p.add_argument("--wg-addr", default="?")
    p.add_argument("--p2p-port", type=int, default=9100)
    p.add_argument("--bootstrap-key", default=None)
    p.add_argument("--show-key", action="store_true")
    args = p.parse_args()

    agent = WorkerAgent(
        args.master, args.master_key, args.wg_addr,
        password=args.password, p2p_port=args.p2p_port,
        bootstrap_pubkey_hex=args.bootstrap_key,
    )

    if args.show_key:
        print(f"Worker public key: {agent.static_pub.hex()}")
        return

    await agent.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped")