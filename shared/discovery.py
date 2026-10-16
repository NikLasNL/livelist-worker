"""
shared/discovery.py — Auto-discovery + health-check.

Discovery: unicast ANNOUNCE на WG peers (не broadcast — WG его не умеет).
Health-check: ping всех известных peer'ов.

Регистрация новых воркеров — через TCP enrollment, не через scan.
"""

import asyncio
import hashlib
import hmac
import ipaddress
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
WG_INTERFACE = "wg-mesh"

TYPE_ANNOUNCE = 0x01
TYPE_PING = 0x02
TYPE_PONG = 0x03


# ═════════════════════════════════════════════════════════════════════
# PSK
# ═════════════════════════════════════════════════════════════════════

def derive_discovery_psk(secret) -> bytes:
    if isinstance(secret, str):
        secret = secret.encode()
    if not secret:
        raise ValueError("Empty secret")
    prk = hmac.new(b"\x00" * 32, secret, hashlib.sha256).digest()
    return hmac.new(prk, b"discovery-psk-v1" + b"\x01",
                     hashlib.sha256).digest()


# ═════════════════════════════════════════════════════════════════════
# Packet
# ═════════════════════════════════════════════════════════════════════

def _build_packet(msg_type: int, psk: bytes,
                    wg_addr: str = "", hostname: str = "") -> bytes:
    nonce = os.urandom(32)
    ts = int(time.time()).to_bytes(8, "big")
    wg_b = wg_addr.encode()
    hn_b = hostname.encode()

    header = (
        MAGIC + bytes([VERSION, msg_type])
        + nonce + ts
        + struct.pack(">H", len(wg_b)) + wg_b
        + struct.pack(">H", len(hn_b)) + hn_b
    )
    sig = hmac.new(psk, header, hashlib.sha256).digest()
    return header + sig


def _parse_packet(data: bytes, psk: bytes) -> Optional[dict]:
    if len(data) < 80 or data[:4] != MAGIC or data[4] != VERSION:
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
        "type": msg_type, "nonce": nonce, "ts": ts,
        "wg_addr": wg_addr, "hostname": hostname,
    }


# ═════════════════════════════════════════════════════════════════════
# UDP send (надёжный, blocking в executor)
# ═════════════════════════════════════════════════════════════════════

def _send_udp_blocking(packet: bytes, peer_ip: str,
                         port: int, timeout: float = 2.0) -> tuple:
    """
    Отправка UDP через connect+send.
    Возвращает (ok, error_msg).
    """
    import ipaddress

    peer_ip_clean = str(peer_ip).strip()
    try:
        ipaddress.IPv4Address(peer_ip_clean)
    except Exception as e:
        return False, f"invalid IP {peer_ip!r}: {e}"

    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            return False, f"invalid port {port!r}"
    except Exception as e:
        return False, f"invalid port {port!r}: {e}"

    if not isinstance(packet, (bytes, bytearray)):
        return False, f"packet not bytes: {type(packet)}"
    if len(packet) == 0 or len(packet) > 65507:
        return False, f"packet size {len(packet)}"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # ⭐ Ключевой fix: connect вместо sendto
            s.connect((peer_ip_clean, port_int))
            n = s.send(bytes(packet))
            if n != len(packet):
                return False, f"sent {n}/{len(packet)}"
            return True, ""
        finally:
            s.close()
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ═════════════════════════════════════════════════════════════════════
# MASTER: unicast broadcaster
# ═════════════════════════════════════════════════════════════════════

class MasterDiscoveryBroadcaster:
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
        self.known_peers = []

    # ─── Read WG peer list ────────────────────────────────────────

    def _get_peers(self) -> list:
        """Список peer-IP в wg-mesh (с sanitize)."""
        result = None

        # sudo -n
        try:
            result = subprocess.run(
                ["sudo", "-n", "wg", "show",
                 self.wg_interface, "allowed-ips"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result = None

        # fallback без sudo
        if result is None or result.returncode != 0:
            try:
                result = subprocess.run(
                    ["wg", "show", self.wg_interface, "allowed-ips"],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception:
                return []

        if result is None or result.returncode != 0:
            return []

        peers = set()
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Формат: "<pubkey>\t<ip1>/32 <ip2>/32"
            # или:    "<pubkey>  <ip1>/32"
            parts = line.replace("\t", " ").split()
            if len(parts) < 2:
                continue

            # parts[0] = pubkey, остальное = CIDRs
            for cidr in parts[1:]:
                if "/32" in cidr:
                    ip = cidr.split("/")[0].strip()
                    try:
                        ipaddress.IPv4Address(ip)
                    except Exception:
                        continue
                    if ip != self.wg_addr:
                        peers.add(ip)

        return sorted(peers)

    # ─── Send one packet ──────────────────────────────────────────

    async def _send_to_peer(self, peer_ip: str, packet: bytes) -> bool:
        loop = asyncio.get_event_loop()
        ok, err = await loop.run_in_executor(
            None, _send_udp_blocking, packet, peer_ip, self.port,
        )
        if ok:
            print(f"[DISCOVERY] → {peer_ip}:{self.port}")
        else:
            print(f"[DISCOVERY] ✗ {peer_ip}: {err}")
        return ok

    # ─── Main loop ────────────────────────────────────────────────

    async def start(self):
        self.running = True
        print(f"[DISCOVERY] Broadcaster started")
        print(f"[DISCOVERY] wg_iface={self.wg_interface} "
              f"self_wg={self.wg_addr} port={self.port}")

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
                        await self._send_to_peer(peer_ip, packet)
                elif first:
                    print("[DISCOVERY] waiting for peers...")
                    first = False

            except Exception as e:
                print(f"[DISCOVERY] loop error: {e}")

            await asyncio.sleep(self.interval)

    async def stop(self):
        self.running = False


# ═════════════════════════════════════════════════════════════════════
# WORKER: listener
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

        try:
            self.sock.bind(("0.0.0.0", self.port))
        except OSError as e:
            print(f"[DISCOVERY] cannot bind :{self.port} — {e}")
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
                    print(f"[DISCOVERY] Master: {src_ip} "
                          f"(wg={parsed['wg_addr']})")
                    try:
                        await self.on_master_found(
                            src_ip, parsed["wg_addr"]
                        )
                    except Exception as e:
                        print(f"[DISCOVERY] callback: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[DISCOVERY] recv: {e}")
                await asyncio.sleep(1)

    async def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()