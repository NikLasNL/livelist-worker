"""
shared/discovery.py — Auto-discovery мастера через UDP unicast.

ВАЖНО: WireGuard — point-to-point, broadcast НЕ поддерживается.
Поэтому master рассылает ANNOUNCE unicast'ом на каждый peer
из `wg show wg-mesh allowed-ips`.

Формат пакета:
  MAGIC(4) || VER(1) || TYPE(1) || NONCE(32) || TS(8) ||
  wg_addr_len(2) || wg_addr || hostname_len(2) || hostname || HMAC(32)
"""

import asyncio
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import time
from typing import Optional, Callable


# ─── Константы ────────────────────────────────────────────────────
MAGIC = b"LLMD"
VERSION = 1
DEFAULT_PORT = 9051
MAX_AGE_SECONDS = 30

TYPE_ANNOUNCE = 0x01
TYPE_QUERY = 0x02
TYPE_RESPONSE = 0x03

WG_INTERFACE = "wg-mesh"


# ═════════════════════════════════════════════════════════════════════
# Crypto helpers
# ═════════════════════════════════════════════════════════════════════

def derive_discovery_psk(secret) -> bytes:
    """
    PSK для discovery.
    secret — bytes (CA private) или str (bootstrap token).
    """
    if isinstance(secret, str):
        secret = secret.encode()

    if not secret:
        raise ValueError("Empty secret")

    prk = hmac.new(b"\x00" * 32, secret, hashlib.sha256).digest()
    return hmac.new(
        prk, b"discovery-psk-v1" + b"\x01", hashlib.sha256
    ).digest()


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
    if len(data) < min_len:
        return None
    if data[:4] != MAGIC:
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

    if len(data) < offset + 32:
        return None

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
# MASTER: unicast broadcaster
# ═════════════════════════════════════════════════════════════════════

class MasterDiscoveryBroadcaster:
    """
    Master рассылает ANNOUNCE unicast'ом на peer-IP из wg-mesh.
    Peer list читается каждые `interval` секунд.
    """

    def __init__(self, psk: bytes,
                 wg_addr: str = "10.10.0.1",
                 hostname: str = "",
                 wg_interface: str = WG_INTERFACE,
                 port: int = DEFAULT_PORT,
                 interval: int = 10):
        self.psk = psk
        self.wg_addr = wg_addr
        self.hostname = hostname or socket.gethostname()
        self.wg_interface = wg_interface
        self.port = port
        self.interval = interval
        self.running = False
        self.sock = None
        self.known_peers = []

    # ─── Read WG peer list ────────────────────────────────────────

    def _get_peers(self) -> list:
        """
        Список peer-IP в wg-mesh.
        Пробует сначала sudo -n (без пароля через sudoers),
        затем без sudo.
        """
        result = None

        # Попытка 1: sudo -n
        try:
            result = subprocess.run(
                ["sudo", "-n", "wg", "show",
                 self.wg_interface, "allowed-ips"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result = None

        # Попытка 2: без sudo
        if result is None or result.returncode != 0:
            try:
                result = subprocess.run(
                    ["wg", "show", self.wg_interface, "allowed-ips"],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception:
                return []

        if result.returncode != 0:
            return []

        peers = []
        for line in result.stdout.strip().splitlines():
            # Формат: "<peer_pubkey>\t<ip1>/32 <ip2>/32 ..."
            parts = line.split("\t")
            if len(parts) < 2:
                parts = line.split()
                if len(parts) < 2:
                    continue
                allowed = parts[1:]
            else:
                allowed = parts[1].split()

            for cidr in allowed:
                if "/32" in cidr:
                    ip = cidr.split("/")[0].strip()
                    if ip and ip != self.wg_addr:
                        peers.append(ip)

        return sorted(set(peers))

    # ─── Main loop ────────────────────────────────────────────────

    async def start(self):
        self.running = True

        print(f"[DISCOVERY] Unicast broadcaster started")
        print(f"[DISCOVERY] wg_iface={self.wg_interface} "
              f"self_wg={self.wg_addr}")
        print(f"[DISCOVERY] interval={self.interval}s port={self.port}")

        loop = asyncio.get_event_loop()
        first = True

        while self.running:
            try:
                peers = self._get_peers()

                if peers != self.known_peers:
                    self.known_peers = peers
                    if peers:
                        print(f"[DISCOVERY] peers: {', '.join(peers)}")
                    elif not first:
                        print("[DISCOVERY] no peers in wg-mesh")

                if peers:
                    packet = _build_packet(
                        TYPE_ANNOUNCE, self.psk,
                        self.wg_addr, self.hostname,
                    )
                    for peer_ip in peers:
                        # Используем blocking socket в executor — надёжнее
                        ok = await loop.run_in_executor(
                            None,
                            self._send_blocking,
                            packet, peer_ip, self.port,
                        )
                        if ok:
                            print(f"[DISCOVERY] → {peer_ip}:{self.port}")

                elif first:
                    print("[DISCOVERY] waiting for peers...")
                    first = False

            except Exception as e:
                print(f"[DISCOVERY] loop error: {e}")

            await asyncio.sleep(self.interval)

    def _send_blocking(self, packet: bytes, peer_ip: str,
                        port: int) -> bool:
        """
        Отправка UDP через свежий blocking socket.
        Работает в отдельном потоке (executor).
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            try:
                s.sendto(packet, (peer_ip, port))
                return True
            finally:
                s.close()
        except Exception as e:
            print(f"[DISCOVERY] send {peer_ip}: {e}")
            return False


# ═════════════════════════════════════════════════════════════════════
# WORKER: listener
# ═════════════════════════════════════════════════════════════════════

class WorkerDiscoveryListener:
    """
    Слушает UDP :9051.
    При валидном ANNOUNCE — вызывает on_master_found().
    """

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
                data, addr = await loop.sock_recvfrom(self.sock, 4096)
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
                        print(f"[DISCOVERY] callback: {e}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[DISCOVERY] recv error: {e}")
                await asyncio.sleep(1)

    async def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass