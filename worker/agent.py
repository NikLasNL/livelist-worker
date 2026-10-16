#!/usr/bin/env python3
"""
worker/agent.py — Worker v8
  + PSK listener на :9052 (bootstrap password rotation)
  + Auto-discovery мастера (unicast)
  + Auto-enroll (bootstrap token)
  + Certificate-based trust
  + Relay capability
  + Module unpack (XOR+checksum)
"""

import asyncio
import json
import logging
import os
import socket
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
from shared.module_pack import unpack_module, derive_xor_key
from shared.ca import verify_certificate
from shared.discovery import (
    WorkerDiscoveryListener, derive_discovery_psk,
)

from worker.loader import ModuleLoader
from worker.executor import TaskExecutor
from worker.p2p import P2PNode
from worker.relay import RelayServer
from worker.psk_listener import PSKListener


# ─── Пути ────────────────────────────────────────────────────────
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

DISCOVERY_PORT = 9051
PSK_PORT = 9052


# ─── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "worker.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("worker")


# ═════════════════════════════════════════════════════════════════════
# WorkerAgent
# ═════════════════════════════════════════════════════════════════════

class WorkerAgent:
    def __init__(self,
                 master_addr=None,
                 master_pubkey_hex=None,
                 wg_addr="?",
                 password=None,
                 p2p_port=9100,
                 bootstrap_token=None,
                 relay_port=9200,
                 bootstrap_password=None):
        # ─── Master addr ─────────────────────────────────────────
        self.master_addr = master_addr or "10.10.0.1:9050"
        ma_file = CONFIG / "master_addr.txt"
        if ma_file.exists():
            saved = ma_file.read_text().strip()
            if saved:
                self.master_addr = saved
                log.info(f"Loaded master_addr: {saved}")

        self.master_pubkey = (bytes.fromhex(master_pubkey_hex)
                              if master_pubkey_hex else None)
        # Try load from file
        if not self.master_pubkey:
            mp = CONFIG / "master_pubkey.txt"
            if mp.exists():
                try:
                    self.master_pubkey = bytes.fromhex(mp.read_text().strip())
                    log.info("Loaded master_pubkey from file")
                except Exception:
                    pass

        self.wg_addr = wg_addr
        self.password = (password or os.environ.get("LIVELIST_PASSWORD")
                          or "changeme-please")
        self.p2p_port = p2p_port
        self.relay_port = relay_port
        self.bootstrap_token = bootstrap_token
        self.bootstrap_password = (bootstrap_password
                                    or os.environ.get("BOOTSTRAP_PASSWORD")
                                    or "")

        # ─── Identity keys ───────────────────────────────────────
        self.key_path = CONFIG / "worker_keys.json"
        if not self.key_path.exists():
            priv, pub = generate_keypair()
            save_keypair(self.key_path, priv, pub)
            log.info(f"New worker key: {pub.hex()}")

        self.static_priv, self.static_pub = load_keypair(self.key_path)

        # ─── Certificate ─────────────────────────────────────────
        self.cert_path = CONFIG / "certificate.json"
        self.cert = None
        if self.cert_path.exists():
            try:
                self.cert = json.loads(self.cert_path.read_text())
                log.info(f"Loaded cert: {self.cert.get('hostname')}")
            except Exception:
                pass

        # ─── CA public ───────────────────────────────────────────
        self.ca_pub_path = CONFIG / "ca_public.txt"
        self.ca_pub = None
        if self.ca_pub_path.exists():
            try:
                self.ca_pub = bytes.fromhex(
                    self.ca_pub_path.read_text().strip()
                )
            except Exception:
                pass

        # ─── Discovery PSK ───────────────────────────────────────
        self.discovery_psk = None
        psk_file = CONFIG / "discovery_psk.txt"
        if psk_file.exists():
            try:
                self.discovery_psk = bytes.fromhex(
                    psk_file.read_text().strip()
                )
            except Exception:
                pass
        if not self.discovery_psk and self.bootstrap_token:
            try:
                self.discovery_psk = derive_discovery_psk(
                    self.bootstrap_token.encode()
                )
            except Exception:
                pass

        self.discovery_listener = None
        self.psk_listener = None

        # ─── Loaders ─────────────────────────────────────────────
        self.loader = ModuleLoader(MODULES_DIR)
        self.executor = TaskExecutor(self.loader)

        # ─── P2P ─────────────────────────────────────────────────
        self.p2p = P2PNode(
            my_priv=self.static_priv,
            my_pub=self.static_pub,
            password=self.password,
            listen_port=self.p2p_port,
            on_data=self._on_p2p_data,
        )

        self.relay = None
        self.running = True
        self.reconnect_delay = 5
        self.max_reconnect_delay = 300

    # ═════════════════════════════════════════════════════════════════
    # Run
    # ═════════════════════════════════════════════════════════════════

    async def run(self):
        log.info("═" * 60)
        log.info(f"Worker v8 | pub={self.static_pub.hex()[:16]}")
        log.info(f"Master: {self.master_addr}")
        log.info(f"WG: {self.wg_addr}  P2P: {self.p2p_port}")
        log.info(f"Enrolled: {'✓' if self.cert else '✗'}")
        log.info(f"Modules: {self.loader.list_modules()}")
        log.info("═" * 60)

        # ─── P2P server ──────────────────────────────────────────
        try:
            await self.p2p.start_server()
        except Exception as e:
            log.warning(f"P2P server: {e}")

        # ─── PSK listener (:9052) ────────────────────────────────
        if self.bootstrap_password:
            try:
                self.psk_listener = PSKListener(
                    bootstrap_password=self.bootstrap_password,
                    port=PSK_PORT,
                    on_master_authenticated=self._on_psk_authenticated,
                )
                asyncio.create_task(self.psk_listener.start())
                log.info(f"PSK listener started on :{PSK_PORT}")
            except Exception as e:
                log.warning(f"PSK listener: {e}")
        else:
            log.info("No BOOTSTRAP_PASSWORD — PSK listener disabled")

        # ─── Discovery listener (:9051) ──────────────────────────
        if self.discovery_psk:
            try:
                self.discovery_listener = WorkerDiscoveryListener(
                    psk=self.discovery_psk,
                    on_master_found=self._on_master_discovered,
                    port=DISCOVERY_PORT,
                )
                asyncio.create_task(self.discovery_listener.start())
                log.info(f"Discovery listener started on :{DISCOVERY_PORT}")
            except Exception as e:
                log.warning(f"Discovery listener: {e}")
        else:
            log.info("No discovery_psk — discovery disabled")

        # ─── Relay ───────────────────────────────────────────────
        if self.cert and self.cert.get("can_relay"):
            try:
                self.relay = RelayServer(
                    my_priv=self.static_priv,
                    my_pub=self.static_pub,
                    password=self.password,
                    ca_pub=self.ca_pub,
                    listen_port=self.relay_port,
                )
                await self.relay.start()
                log.info(f"Relay enabled on :{self.relay_port}")
            except Exception as e:
                log.warning(f"Relay: {e}")

        # ─── Main loop ───────────────────────────────────────────
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

        # ─── Shutdown ────────────────────────────────────────────
        if self.discovery_listener:
            await self.discovery_listener.stop()
        if self.psk_listener:
            await self.psk_listener.stop()
        if self.relay:
            await self.relay.stop()
        await self.p2p.stop()
        log.info("Stopped")

    # ═════════════════════════════════════════════════════════════════
    # PSK callback
    # ═════════════════════════════════════════════════════════════════

    async def _on_psk_authenticated(self, master_ip: str,
                                      master_pubkey: bytes):
        log.info(f"[PSK] Master authenticated: {master_ip}")
        log.info(f"[PSK] Master pubkey: {master_pubkey.hex()[:16]}...")
        # Сохраняем адрес мастера для будущих коннектов
        try:
            (CONFIG / "master_addr.txt").write_text(f"{master_ip}:9050")
            (CONFIG / "master_addr.txt").chmod(0o600)
        except Exception as e:
            log.warning(f"[PSK] save master_addr: {e}")

    # ═════════════════════════════════════════════════════════════════
    # Discovery callback
    # ═════════════════════════════════════════════════════════════════

    async def _on_master_discovered(self, src_ip: str,
                                      master_wg_addr: str):
        new_addr = f"{master_wg_addr}:9050"
        if new_addr != self.master_addr:
            log.info(f"[DISCOVERY] Master switched: "
                      f"{self.master_addr} → {new_addr}")
            self.master_addr = new_addr
            try:
                (CONFIG / "master_addr.txt").write_text(new_addr)
                (CONFIG / "master_addr.txt").chmod(0o600)
            except Exception:
                pass
        else:
            log.info(f"[DISCOVERY] Master confirmed: {new_addr}")

    # ═════════════════════════════════════════════════════════════════
    # TCP session с мастером
    # ═════════════════════════════════════════════════════════════════

    async def _run_session(self):
        if not self.master_pubkey and not self.cert:
            log.warning("No master_pubkey and no cert — waiting...")
            await asyncio.sleep(10)
            raise ConnectionRefusedError("no master pubkey")

        host, port = self.master_addr.rsplit(":", 1)
        port = int(port)

        log.info(f"Connecting to {host}:{port}...")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=15,
        )

        # ─── ECDH + 2FA handshake ────────────────────────────────
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

        # ─── Enrollment / Announce ───────────────────────────────
        if self.cert is None:
            if not self.bootstrap_token:
                log.error("No cert and no bootstrap_token")
                return

            log.info("First-time enrollment...")

            # Public IP для relay-capability
            my_public_ip = ""
            try:
                import aiohttp
                async with aiohttp.ClientSession() as s:
                    async with s.get(
                        "https://api.ipify.org",
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as r:
                        my_public_ip = (await r.text()).strip()
            except Exception:
                pass

            can_relay = bool(my_public_ip)
            hostname = socket.gethostname()

            await write_message(writer, channel,
                                 MsgType.ENROLL_REQUEST, {
                "token": self.bootstrap_token,
                "wg_addr": self.wg_addr,
                "hostname": hostname,
                "public_ip": my_public_ip,
                "can_relay": can_relay,
                "pubkey": self.static_pub.hex(),
            })

            msg_type, header, body = await read_message(reader, channel)

            if msg_type == MsgType.ENROLL_REJECT:
                log.error(f"Rejected: {header.get('reason')}")
                return

            if msg_type != MsgType.ENROLL_RESPONSE:
                log.error(f"Unexpected: {msg_type}")
                return

            self.cert = header.get("cert")
            ca_public_hex = header.get("ca_public")
            discovery_psk_hex = header.get("discovery_psk")

            if ca_public_hex:
                self.ca_pub = bytes.fromhex(ca_public_hex)
                self.ca_pub_path.write_text(ca_public_hex)
                self.ca_pub_path.chmod(0o600)
                log.info("CA public stored")

            if discovery_psk_hex:
                self.discovery_psk = bytes.fromhex(discovery_psk_hex)
                psk_file = CONFIG / "discovery_psk.txt"
                psk_file.write_text(discovery_psk_hex)
                psk_file.chmod(0o600)
                log.info("Discovery PSK received")

            self.cert_path.write_text(json.dumps(self.cert, indent=2))
            self.cert_path.chmod(0o600)

            log.info(f"✓ Certificate issued")
            log.info(f"  hostname:  {self.cert.get('hostname')}")
            log.info(f"  wg_addr:   {self.cert.get('wg_addr')}")
            log.info(f"  can_relay: {self.cert.get('can_relay')}")

            if can_relay and not self.relay:
                try:
                    self.relay = RelayServer(
                        my_priv=self.static_priv,
                        my_pub=self.static_pub,
                        password=self.password,
                        ca_pub=self.ca_pub,
                        listen_port=self.relay_port,
                    )
                    await self.relay.start()
                    log.info(f"Relay enabled: {self.relay_port}")
                except Exception as e:
                    log.warning(f"Relay: {e}")

        else:
            # Уже enrolled
            if self.ca_pub and not verify_certificate(
                    self.ca_pub, self.cert):
                log.warning("Cert invalid — re-enrolling")
                self.cert = None
                self.cert_path.unlink(missing_ok=True)
                return

            await write_message(writer, channel,
                                 MsgType.PEER_ANNOUNCE, {
                "cert": self.cert,
            })
            log.info(f"Announced: {self.cert.get('hostname')}")

        # ─── STATUS ──────────────────────────────────────────────
        await write_message(writer, channel, MsgType.STATUS, {
            "state": "online",
            "wg_addr": self.wg_addr,
            "p2p_port": self.p2p_port,
            "relay_port": self.relay_port if self.relay else 0,
            "modules": self.loader.list_modules(),
            "version": "8.0",
            "hostname": self.cert.get("hostname", "?"),
            "can_relay": self.cert.get("can_relay", False),
        })

        await write_message(writer, channel, MsgType.DIRECTORY_REQUEST)

        if not self.loader.list_modules():
            await write_message(writer, channel,
                                 MsgType.REQUEST_MODULES)

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
                await self._unpack_and_load(writer, channel,
                                             header["module"], body)

            elif msg_type == MsgType.MODULE_CHUNK_START:
                fn = header["filename"]
                receivers[fn] = {
                    "buffer": bytearray(),
                    "module": header.get("module") or fn.replace(".py", ""),
                }

            elif msg_type == MsgType.MODULE_CHUNK_CHUNK:
                fn = header["filename"]
                if fn in receivers:
                    receivers[fn]["buffer"].extend(body)

            elif msg_type == MsgType.MODULE_CHUNK_DONE:
                fn = header["filename"]
                if fn in receivers:
                    packed = bytes(receivers[fn]["buffer"])
                    module_name = receivers[fn]["module"]
                    del receivers[fn]
                    await self._unpack_and_load(writer, channel,
                                                 module_name, packed)

            elif msg_type == MsgType.PUSH_VPN:
                await self._handle_vpn(writer, channel, header, body)

            elif msg_type == MsgType.PUSH_UA:
                (BASE / "ua_json.json").write_bytes(body)
                log.info("UA updated")

            elif msg_type == MsgType.RUN_TASK:
                asyncio.create_task(
                    self._handle_task(writer, channel, header, body)
                )

            elif msg_type == MsgType.RELOAD:
                self.loader.reload_all()
                await write_message(writer, channel, MsgType.MODULE_ACK, {
                    "module": "*", "state": "reloaded",
                })

            elif msg_type == MsgType.P2P_CONNECT:
                asyncio.create_task(self._handle_p2p_connect(header))

            elif msg_type == MsgType.DIRECTORY_RESPONSE:
                peers = header.get("peers", [])
                ca_pub_hex = header.get("ca_public")
                if ca_pub_hex and not self.ca_pub:
                    self.ca_pub = bytes.fromhex(ca_pub_hex)
                    self.ca_pub_path.write_text(ca_pub_hex)
                    self.ca_pub_path.chmod(0o600)

                log.info(f"Directory: {len(peers)} peers")
                for p in peers:
                    caps = p.get("capabilities", {})
                    log.info(f"  {caps.get('hostname', '?')} "
                              f"wg={caps.get('wg_addr')} "
                              f"relay={caps.get('can_relay')}")

            elif msg_type == MsgType.KEY_ROTATE_REQUEST:
                await self._handle_key_rotate_request(writer, channel)

            elif msg_type == MsgType.KEY_ROTATE_ACK:
                await self._handle_key_rotate_ack(writer, channel, header)

            elif msg_type == MsgType.SHUTDOWN:
                log.warning("Shutdown from master")
                self.running = False
                return

    # ═════════════════════════════════════════════════════════════════
    # Handlers
    # ═════════════════════════════════════════════════════════════════

    async def _unpack_and_load(self, writer, channel,
                                 module_name, packed):
        if not channel.shared_secret:
            log.error("No shared_secret")
            return False

        try:
            xor_key = derive_xor_key(channel.shared_secret, module_name)
            name, source = unpack_module(packed, xor_key)
        except Exception as e:
            log.error(f"Unpack {module_name}: {e}")
            await write_message(writer, channel, MsgType.MODULE_ACK, {
                "module": module_name, "state": "error",
                "error": str(e),
            })
            return False

        filepath = MODULES_DIR / f"{name}.py"
        filepath.write_bytes(source)
        log.info(f"Unpacked: {name} ({len(source)} bytes)")

        try:
            self.loader.load_module(name)
            await write_message(writer, channel, MsgType.MODULE_ACK, {
                "module": name, "state": "loaded", "size": len(source),
            })
            log.info(f"Module loaded: {name}")
            return True
        except Exception as e:
            log.error(f"Load {name}: {e}")
            await write_message(writer, channel, MsgType.MODULE_ACK, {
                "module": name, "state": "error", "error": str(e),
            })
            return False

    async def _handle_vpn(self, writer, channel, header, body):
        filename = header.get("filename", "wg-new.conf")
        tmp = Path.home() / f".{filename}"
        tmp.write_bytes(body)
        tmp.chmod(0o600)
        try:
            import subprocess
            subprocess.run(
                ["sudo", "cp", str(tmp),
                 f"/etc/wireguard/{filename}"],
                check=True, timeout=10,
            )
            subprocess.run(
                ["sudo", "chmod", "600",
                 f"/etc/wireguard/{filename}"],
                check=True, timeout=10,
            )
            log.info(f"VPN installed: {filename}")
        except Exception as e:
            log.error(f"VPN install: {e}")

    async def _handle_p2p_connect(self, header):
        peer_pub = header.get("peer_pub")
        peer_host = header.get("peer_host")
        peer_port = header.get("peer_port")
        role = header.get("role", "listener")
        log.info(f"[P2P] {role} → {peer_pub[:16]} @ {peer_host}:{peer_port}")

        if role == "initiator":
            if peer_host in ("?", "", None):
                return
            await asyncio.sleep(2)
            await self.p2p.connect_to_peer(peer_host, peer_port, peer_pub)
        else:
            try:
                self.p2p.allowed_peers.add(bytes.fromhex(peer_pub))
            except Exception:
                pass

    async def _on_p2p_data(self, peer_pub_hex, msg_type, header, body):
        log.info(f"[P2P] {peer_pub_hex[:16]}: {msg_type}")

    async def _handle_key_rotate_request(self, writer, channel):
        log.info("[KEY] rotation requested")
        old_priv, old_pub, new_priv, new_pub = rotate_keypair(
            self.key_path, KEYS_BACKUP
        )
        self.static_priv = new_priv
        self.static_pub = new_pub
        self.p2p.my_priv = new_priv
        self.p2p.my_pub = new_pub
        await write_message(writer, channel, MsgType.KEY_ROTATE_NEW, {
            "new_pub": new_pub.hex(),
            "old_pub": old_pub.hex(),
        })

    async def _handle_key_rotate_ack(self, writer, channel, header):
        new_master_pub_hex = header.get("new_pub")
        if new_master_pub_hex:
            self.master_pubkey = bytes.fromhex(new_master_pub_hex)
            (CONFIG / "master_pubkey.txt").write_text(new_master_pub_hex)
            log.info(f"[KEY] master rotated: {new_master_pub_hex[:16]}")
        await write_message(writer, channel, MsgType.KEY_ROTATE_DONE, {
            "state": "acknowledged",
        })

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
            log.info(f"Task {task_id} done ({len(result_bytes)} bytes)")

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
    p.add_argument("--master", default=None)
    p.add_argument("--master-key", default=None)
    p.add_argument("--password", default=None)
    p.add_argument("--bootstrap-token", default=None)
    p.add_argument("--bootstrap-password", default=None)
    p.add_argument("--wg-addr", default="?")
    p.add_argument("--p2p-port", type=int, default=9100)
    p.add_argument("--relay-port", type=int, default=9200)
    p.add_argument("--show-key", action="store_true")
    args = p.parse_args()

    # master_pubkey fallback
    master_pubkey = args.master_key
    if not master_pubkey:
        mp = Path.home() / "livelist-worker/config/master_pubkey.txt"
        if mp.exists():
            master_pubkey = mp.read_text().strip()

    agent = WorkerAgent(
        master_addr=args.master,
        master_pubkey_hex=master_pubkey,
        wg_addr=args.wg_addr,
        password=args.password,
        p2p_port=args.p2p_port,
        bootstrap_token=args.bootstrap_token,
        relay_port=args.relay_port,
        bootstrap_password=args.bootstrap_password,
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