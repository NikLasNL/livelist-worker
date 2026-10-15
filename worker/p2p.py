"""
worker/p2p.py — Полный P2P воркер↔воркер.

Server + Client + messaging.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.crypto import (
    Handshake, load_keypair, generate_keypair,
    EncryptedChannel, derive_session_keys, dh,
)
from shared.protocol import (
    MsgType, read_message, write_message,
)


class P2PPeer:
    """Один peer (соединение)."""

    def __init__(self, pubkey, reader, writer, channel, addr, is_initiator):
        self.pubkey = pubkey
        self.pubkey_hex = pubkey.hex()
        self.reader = reader
        self.writer = writer
        self.channel = channel
        self.addr = addr
        self.is_initiator = is_initiator
        self.lock = asyncio.Lock()
        self.handler = None  # callback для входящих данных

    async def send(self, msg_type, header=None, body=b""):
        async with self.lock:
            await write_message(self.writer, self.channel,
                                 msg_type, header, body)

    async def recv(self):
        return await read_message(self.reader, self.channel)

    async def close(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


class P2PNode:
    """
    P2P узел. Умеет:
      • Слушать входящие (server)
      • Подключаться к peers (client)
      • Отправлять/принимать P2P-сообщения
    """

    def __init__(self, my_priv, my_pub, password,
                 listen_port=0, listen_host="0.0.0.0",
                 on_data=None):
        self.my_priv = my_priv
        self.my_pub = my_pub
        self.password = password
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.on_data = on_data        # callback: async (peer_pub_hex, msg_type, header, body)
        self.peers = {}               # pubkey_hex → P2PPeer
        self.server = None
        self.allowed_peers = set()    # из master
        self.running = True

    # ═════════════════════════════════════════════════════════════════
    # Server side — входящие
    # ═════════════════════════════════════════════════════════════════

    async def start_server(self):
        self.server = await asyncio.start_server(
            self._handle_incoming, self.listen_host, self.listen_port
        )
        addrs = ", ".join(str(s.getsockname()) for s in self.server.sockets)
        print(f"[P2P] server listening on {addrs}")

    async def _handle_incoming(self, reader, writer):
        addr = writer.get_extra_info("peername")
        print(f"[P2P] incoming from {addr}")

        try:
            channel, peer_pub = await asyncio.wait_for(
                Handshake.server_handshake(
                    reader, writer,
                    my_static_priv=self.my_priv,
                    allowed_clients=self.allowed_peers,
                    password=self.password,
                ),
                timeout=15,
            )
            peer = P2PPeer(peer_pub, reader, writer, channel, addr,
                            is_initiator=False)
            self.peers[peer.pubkey_hex] = peer
            print(f"[P2P] + peer {peer.pubkey_hex[:16]} (incoming)")

            # Run peer loop
            await self._peer_loop(peer)

        except PermissionError as e:
            print(f"[P2P] reject {addr}: {e}")
        except asyncio.TimeoutError:
            print(f"[P2P] timeout {addr}")
        except Exception as e:
            print(f"[P2P] error {addr}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ═════════════════════════════════════════════════════════════════
    # Client side — исходящие
    # ═════════════════════════════════════════════════════════════════

    async def connect_to_peer(self, peer_host, peer_port, peer_static_pub):
        """Подключиться к другому воркеру."""
        peer_pub_hex = peer_static_pub.hex() if isinstance(peer_static_pub, bytes) \
                        else peer_static_pub

        if peer_pub_hex in self.peers:
            print(f"[P2P] already connected to {peer_pub_hex[:16]}")
            return self.peers[peer_pub_hex]

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(peer_host, peer_port),
                timeout=15,
            )
            peer_pub_bytes = bytes.fromhex(peer_pub_hex)
            channel = await asyncio.wait_for(
                Handshake.client_handshake(
                    reader, writer,
                    my_static_priv=self.my_priv,
                    server_static_pub=peer_pub_bytes,
                    password=self.password,
                ),
                timeout=15,
            )
            peer = P2PPeer(peer_pub_bytes, reader, writer, channel,
                            (peer_host, peer_port), is_initiator=True)
            self.peers[peer_pub_hex] = peer
            print(f"[P2P] + peer {peer_pub_hex[:16]} (outgoing)")

            # Запускаем receive loop в фоне
            asyncio.create_task(self._peer_loop(peer))

            return peer

        except Exception as e:
            print(f"[P2P] connect {peer_host}:{peer_port} failed: {e}")
            return None

    # ═════════════════════════════════════════════════════════════════
    # Peer loop — приём сообщений
    # ═════════════════════════════════════════════════════════════════

    async def _peer_loop(self, peer: P2PPeer):
        try:
            while self.running:
                msg_type, header, body = await peer.recv()

                if msg_type == MsgType.P2P_DATA:
                    if self.on_data:
                        try:
                            await self.on_data(
                                peer.pubkey_hex, msg_type, header, body
                            )
                        except Exception as e:
                            print(f"[P2P] on_data err: {e}")

                elif msg_type == MsgType.PING:
                    await peer.send(MsgType.PONG)

                elif msg_type == MsgType.P2P_DISCONNECT:
                    print(f"[P2P] peer {peer.pubkey_hex[:16]} disconnect")
                    break

                else:
                    # Проброс в on_data для любого другого типа
                    if self.on_data:
                        try:
                            await self.on_data(
                                peer.pubkey_hex, msg_type, header, body
                            )
                        except Exception:
                            pass

        except (asyncio.IncompleteReadError, ConnectionResetError,
                asyncio.CancelledError):
            pass
        except Exception as e:
            print(f"[P2P] peer loop err {peer.pubkey_hex[:16]}: {e}")
        finally:
            if peer.pubkey_hex in self.peers:
                del self.peers[peer.pubkey_hex]
            print(f"[P2P] - peer {peer.pubkey_hex[:16]}")

    # ═════════════════════════════════════════════════════════════════
    # Send to peer
    # ═════════════════════════════════════════════════════════════════

    async def send_to_peer(self, peer_pub_hex, msg_type, header=None, body=b""):
        peer = self.peers.get(peer_pub_hex)
        if not peer:
            raise RuntimeError(f"No P2P to {peer_pub_hex[:16]}")
        await peer.send(msg_type, header, body)

    async def broadcast(self, msg_type, header=None, body=b""):
        for pub_hex in list(self.peers.keys()):
            try:
                await self.peers[pub_hex].send(msg_type, header, body)
            except Exception as e:
                print(f"[P2P] broadcast err {pub_hex[:16]}: {e}")

    def list_peers(self):
        return [{
            "pubkey": p.pubkey_hex,
            "addr": str(p.addr),
            "is_initiator": p.is_initiator,
        } for p in self.peers.values()]

    # ═════════════════════════════════════════════════════════════════
    # Stop
    # ═════════════════════════════════════════════════════════════════

    async def stop(self):
        self.running = False
        for peer in list(self.peers.values()):
            await peer.close()
        self.peers.clear()
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass