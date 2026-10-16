"""
worker/psk_listener.py — VPS слушает HELLO от мастера.

На первом коннекте:
  - Принимает HELLO, зашифрованный bootstrap-паролем
  - Генерирует свой eph keypair
  - Извлекает новый пароль через ECDH
  - Сохраняет новый пароль
  - Сообщает мастеру

На последующих:
  - Использует сохранённый пароль
  - После успеха снова ротирует
"""

import asyncio
import hashlib
import hmac
import json
import os
import socket
import struct
import time
from pathlib import Path

from shared.psk_auth import (
    PSKError, TYPE_HELLO, TYPE_REPLY,
    pack_packet, unpack_packet, decrypt_packet,
    derive_key_from_password, derive_key_from_dh,
    generate_x25519_keypair, x25519_dh,
    EPH_LEN, NONCE_LEN, HEADER_LEN,
)


DEFAULT_PORT = 9052
STATE_FILE = Path.home() / "livelist-worker/config/psk_state.json"


class PSKListener:
    def __init__(self, bootstrap_password: str, port: int = DEFAULT_PORT,
                 on_master_authenticated=None):
        self.bootstrap_password = bootstrap_password
        self.port = port
        self.sock = None
        self.running = False
        self.on_authenticated = on_master_authenticated
        self.state = self._load_state()
        self.static_priv, self.static_pub = self._get_static_keypair()

    # ─── Persistent state ────────────────────────────────────────

    def _load_state(self) -> dict:
        if not STATE_FILE.exists():
            return {"current_password": None, "master_pubkey": None}
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            return {"current_password": None, "master_pubkey": None}

    def _save_state(self):
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(self.state, indent=2))
        STATE_FILE.chmod(0o600)

    def _get_static_keypair(self) -> tuple:
        key_file = STATE_FILE.parent / "vps_identity.json"
        if key_file.exists():
            data = json.loads(key_file.read_text())
            return bytes.fromhex(data["priv"]), bytes.fromhex(data["pub"])
        priv, pub = generate_x25519_keypair()
        key_file.write_text(json.dumps({
            "priv": priv.hex(), "pub": pub.hex(),
        }))
        key_file.chmod(0o600)
        return priv, pub

    # ─── Lifecycle ───────────────────────────────────────────────

    async def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.setblocking(False)

        print(f"[PSK] Listener on 0.0.0.0:{self.port}")
        if self.state.get("current_password"):
            print(f"[PSK] State: enrolled (uses rotated password)")
        else:
            print(f"[PSK] State: bootstrap (waiting for first contact)")

        loop = asyncio.get_event_loop()
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, 4096)
                await self._handle(data, addr, loop)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[PSK] recv error: {e}")
                await asyncio.sleep(0.5)

    async def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    # ─── Handle incoming ─────────────────────────────────────────

    async def _handle(self, data: bytes, addr: tuple, loop):
        master_ip = addr[0]
        try:
            parsed = unpack_packet(data)
        except PSKError as e:
            print(f"[PSK] malformed from {master_ip}: {e}")
            return

        if parsed["type"] != TYPE_HELLO:
            print(f"[PSK] unexpected type={parsed['type']}")
            return

        # Определяем, какой пароль использовать
        if self.state.get("current_password"):
            # Уже enrolled — используем ротированный пароль
            pwd = self.state["current_password"]
            mode = "enrolled"
        else:
            # Первый контакт — bootstrap
            pwd = self.bootstrap_password
            mode = "bootstrap"

        key = derive_key_from_password(pwd)

        try:
            payload = decrypt_packet(parsed, key)
        except PSKError as e:
            print(f"[PSK] auth failed from {master_ip}: {e}")
            return

        # payload = kali_static_pub(32) || hostname
        if len(payload) < 32:
            print(f"[PSK] payload too short")
            return

        kali_static_pub = payload[:32]
        print(f"[PSK] ✓ Authenticated from {master_ip} "
              f"(mode={mode}, kali_pub={kali_static_pub.hex()[:16]}...)")

        # Генерируем новый пароль
        if mode == "bootstrap":
            # Первое enrollment: master присылает свой eph_pub в parsed
            # Вычисляем shared secret через ECDH
            vps_eph_priv, vps_eph_pub = generate_x25519_keypair()

            dh = x25519_dh(vps_eph_priv, parsed["eph_pub"])
            ctx = parsed["nonce"] + os.urandom(NONCE_LEN)
            session_key = derive_key_from_dh(dh, ctx)

            new_password = os.urandom(32).hex()
            print(f"[PSK] Generating new password: "
                  f"{new_password[:16]}...")

            # Отправляем REPLY
            reply_plain = (
                int(time.time()).to_bytes(8, "big")
                + new_password.encode()
            )
            reply = pack_packet(
                TYPE_REPLY, vps_eph_pub, ctx[NONCE_LEN:],
                session_key, reply_plain,
            )
            await loop.sock_sendto(self.sock, reply, addr)

            # Сохраняем состояние
            self.state["current_password"] = new_password
            self.state["master_pubkey"] = kali_static_pub.hex()
            self._save_state()
            print(f"[PSK] ✓ Rotated to new password, state saved")

            # Callback
            if self.on_authenticated:
                try:
                    await self.on_authenticated(master_ip, kali_static_pub)
                except Exception as e:
                    print(f"[PSK] callback error: {e}")

        else:
            # Уже enrolled — просто подтверждаем
            confirm = (
                int(time.time()).to_bytes(8, "big")
                + b"ack"
            )
            reply = pack_packet(
                TYPE_REPLY, self.static_pub, parsed["nonce"],
                key, confirm,
            )
            await loop.sock_sendto(self.sock, reply, addr)

            # Опционально: ротация при каждом коннекте
            new_password = os.urandom(32).hex()
            # ... но нужно согласование с master
            # Пока оставляем стабильным