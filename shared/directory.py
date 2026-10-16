"""
shared/discovery.py — Auto-discovery мастера через UDP broadcast в WG-сети.

Master шлёт ANNOUNCE с HMAC(PSK, nonce||ts).
Worker проверяет, узнаёт src IP мастера.

Пакет:
  MAGIC(4) || ver(1) || type(1) || nonce(32) || ts(8) ||
  wg_addr_len(2) || wg_addr || hostname_len(2) || hostname || HMAC(32)
"""

import asyncio
import hashlib
import hmac
import os
import socket
import struct
import time
from typing import Optional, Callable


MAGIC = b"LLMD"
VERSION = 1
DEFAULT_PORT = 9051
DEFAULT_BROADCAST = "10.10.0.255"
MAX_AGE_SECONDS = 30

TYPE_ANNOUNCE = 0x01
TYPE_QUERY = 0x02
TYPE_RESPONSE = 0x03


def derive_discovery_psk(secret: bytes) -> bytes:
    """PSK для discovery — HKDF от bootstrap-секрета."""
    if not secret:
        raise ValueError("Empty secret")
    prk = hmac.new(b"\x00" * 32, secret, hashlib.sha256).digest()
    return hmac.new(prk, b"discovery-psk-v1" + b"\x01",
                     hashlib.sha256).digest()


def _build_packet(msg_type: int, psk: bytes,
                    wg_addr: str = "", hostname: str = "") -> bytes:
    nonce = os.urandom(32)
    ts = int(time.time()).to_bytes(8, "big")

    wg_b = wg_addr.encode()
    hn_b = hostname.encode()

    header = (
        MAGIC
        + bytes([VERSION, msg_type])
        + nonce
        + ts
        + struct.pack(">H", len(wg_b)) + wg_b
        + struct.pack(">H", len(hn_b)) + hn_b
    )

    sig = hmac.new(psk, header, hashlib.sha256).digest()
    return header + sig


def _parse_packet(data: bytes, psk: bytes) -> Optional[dict]:
    min_len = 4 + 2 + 32 + 8 + 2 + 2 + 32
    if len(data) < min_len or data[:4] != MAGIC:
        return None

    ver = data[4]
    if ver != VERSION:
        return None

    msg_type = data[5]
    nonce = data[6:38]
    ts = int.from_bytes(data[38:46], "big")

    if abs(time.time() - ts) > MAX_AGE_SECONDS:
        return None

    offset = 46
    wg_len = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    wg_addr = data[offset:offset + wg_len].decode(errors="replace")
    offset += wg_len

    hn_len = struct.unpack(">H", data[offset:offset + 2])[0]
    offset += 2
    hostname = data[offset:offset + hn_len].decode(errors="replace")
    offset += hn_len

    sig = data[offset:offset + 32]
    expected = hmac.new(psk, data[:offset], hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None

    return {
        "type": msg_type,
        "nonce": nonce,
        "ts": ts,
        "wg_addr": wg_addr,
        "hostname": hostname,
    }


# ═════════════════════════════════════════════════════════════════════
# Master: broadcaster
# ═════════════════════════════════════════════════════════════════════

class MasterDiscoveryBroadcaster:
    def __init__(self, psk: bytes,
                 wg_addr: str = "10.10.0.1",
                 hostname: str = "",
                 broadcast_addr: str = DEFAULT_BROADCAST,
                 port: int = DEFAULT_PORT,
                 interval: int = 10):
        self.psk = psk
        self.wg_addr = wg_addr
        self.hostname = hostname or socket.gethostname()
        self.broadcast_addr = broadcast_addr
        self.port = port
        self.interval = interval
        self.running = False
        self.sock = None

    async def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setblocking(False)

        print(f"[DISCOVERY] Broadcaster → "
              f"{self.broadcast_addr}:{self.port} every {self.interval}s")

        loop = asyncio.get_event_loop()
        while self.running:
            try:
                packet = _build_packet(
                    TYPE_ANNOUNCE, self.psk,
                    self.wg_addr, self.hostname,
                )
                await loop.sock_sendto(
                    self.sock, packet,
                    (self.broadcast_addr, self.port),
                )
            except Exception as e:
                print(f"[DISCOVERY] Broadcast error: {e}")

            await asyncio.sleep(self.interval)

    async def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()


# ═════════════════════════════════════════════════════════════════════
# Worker: listener
# ═════════════════════════════════════════════════════════════════════

class WorkerDiscoveryListener:
    def __init__(self, psk: bytes,
                 on_master_found: Callable,
                 port: int = DEFAULT_PORT):
        self.psk = psk
        self.on_master_found = on_master_found
        self.port = port
        self.running = False
        self.sock = None
        self.last_master = None

    async def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            self.sock.bind(("0.0.0.0", self.port))
        except OSError as e:
            print(f"[DISCOVERY] Cannot bind :{self.port} — {e}")
            return

        self.sock.setblocking(False)
        print(f"[DISCOVERY] Listener on 0.0.0.0:{self.port}")

        loop = asyncio.get_event_loop()
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self.sock, 2048)
                src_ip = addr[0]
                parsed = _parse_packet(data, self.psk)
                if not parsed or parsed["type"] != TYPE_ANNOUNCE:
                    continue

                new = (src_ip, parsed["wg_addr"])
                if new != self.last_master:
                    self.last_master = new
                    print(f"[DISCOVERY] Master found: {src_ip} "
                          f"(wg={parsed['wg_addr']}, "
                          f"host={parsed['hostname']})")
                    try:
                        await self.on_master_found(
                            src_ip, parsed["wg_addr"]
                        )
                    except Exception as e:
                        print(f"[DISCOVERY] Callback: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[DISCOVERY] Recv: {e}")
                await asyncio.sleep(1)

    async def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()