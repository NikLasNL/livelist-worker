"""
worker/relay.py — Relay для других воркеров.

Воркер с can_relay=True может принимать relay-запросы.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.protocol import MsgType, read_message, write_message
from shared.crypto import Handshake


class RelayServer:
    def __init__(self, my_priv, my_pub, password, ca_pub,
                 listen_port=9200, listen_host="0.0.0.0"):
        self.my_priv = my_priv
        self.my_pub = my_pub
        self.password = password
        self.ca_pub = ca_pub
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server = None
        self.tunnels = {}
        self.counter = 0

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_relay_client, self.listen_host, self.listen_port
        )
        addrs = ", ".join(str(s.getsockname()) for s in self.server.sockets)
        print(f"[RELAY] Listening on {addrs}")

    async def _handle_relay_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        print(f"[RELAY] Incoming from {peer}")

        try:
            channel, client_pub = await asyncio.wait_for(
                Handshake.server_handshake(
                    reader, writer,
                    my_static_priv=self.my_priv,
                    allowed_clients=set(),
                    password=self.password,
                ),
                timeout=15,
            )

            msg_type, header, body = await read_message(reader, channel)

            if msg_type == MsgType.RELAY_HELLO:
                target_pub = header.get("target_pub")
                target_addr = header.get("target_addr")

                print(f"[RELAY] {client_pub.hex()[:16]} → {target_pub[:16]}")

                try:
                    t_reader, t_writer = await asyncio.wait_for(
                        asyncio.open_connection(*target_addr),
                        timeout=10,
                    )
                except Exception as e:
                    print(f"[RELAY] Cannot reach target: {e}")
                    writer.close()
                    return

                self.counter += 1
                tunnel_id = f"tunnel-{self.counter}"

                self.tunnels[tunnel_id] = {
                    "client_reader": reader,
                    "client_writer": writer,
                    "client_channel": channel,
                    "target_reader": t_reader,
                    "target_writer": t_writer,
                }

                await write_message(writer, channel,
                                     MsgType.RELAY_OPEN, {
                    "tunnel_id": tunnel_id,
                    "status": "ok",
                })

                asyncio.create_task(self._forward_c2t(tunnel_id))
                asyncio.create_task(self._forward_t2c(tunnel_id))

            elif msg_type == MsgType.PING:
                await write_message(writer, channel, MsgType.PONG)

        except Exception as e:
            print(f"[RELAY] Error {peer}: {e}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _forward_c2t(self, tunnel_id):
        t = self.tunnels.get(tunnel_id)
        if not t:
            return
        try:
            while True:
                msg_type, header, body = await read_message(
                    t["client_reader"], t["client_channel"]
                )
                if msg_type == MsgType.RELAY_CLOSE:
                    break
                if msg_type == MsgType.RELAY_DATA:
                    t["target_writer"].write(body)
                    await t["target_writer"].drain()
        except Exception:
            pass
        finally:
            await self._close_tunnel(tunnel_id)

    async def _forward_t2c(self, tunnel_id):
        t = self.tunnels.get(tunnel_id)
        if not t:
            return
        try:
            while True:
                data = await t["target_reader"].read(65536)
                if not data:
                    break
                await write_message(
                    t["client_writer"], t["client_channel"],
                    MsgType.RELAY_DATA, {}, body=data,
                )
        except Exception:
            pass
        finally:
            await self._close_tunnel(tunnel_id)

    async def _close_tunnel(self, tunnel_id):
        t = self.tunnels.pop(tunnel_id, None)
        if not t:
            return
        for w in (t.get("client_writer"), t.get("target_writer")):
            if w:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass

    async def stop(self):
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass