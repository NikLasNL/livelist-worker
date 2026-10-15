"""
shared/protocol.py — wire format v3
+ P2P messaging
+ Key rotation
"""

import json
import struct
import hashlib


class MsgType:
    # Handshake
    HELLO = "hello"
    WELCOME = "welcome"

    # Info
    PING = "ping"
    PONG = "pong"
    STATUS = "status"
    PEER_LIST = "peer_list"

    # Modules
    PUSH_MODULE = "push_module"
    MODULE_ACK = "module_ack"
    MODULE_CHUNK_START = "module_chunk_start"
    MODULE_CHUNK_CHUNK = "module_chunk_chunk"
    MODULE_CHUNK_DONE = "module_chunk_done"

    # Configs
    PUSH_VPN = "push_vpn"
    PUSH_UA = "push_ua"

    # Tasks
    RUN_TASK = "run_task"
    TASK_RESULT = "task_result"
    TASK_RESULT_CHUNK_START = "task_result_chunk_start"
    TASK_RESULT_CHUNK_CHUNK = "task_result_chunk_chunk"
    TASK_RESULT_CHUNK_DONE = "task_result_chunk_done"
    TASK_ERROR = "task_error"

    # Control
    SHUTDOWN = "shutdown"
    RELOAD = "reload"
    REQUEST_MODULES = "request_modules"

    # ⭐ P2P
    P2P_CONNECT = "p2p_connect"         # master → worker: "connect to peer"
    P2P_HELLO = "p2p_hello"
    P2P_WELCOME = "p2p_welcome"
    P2P_DATA = "p2p_data"               # peer-to-peer payload
    P2P_DISCONNECT = "p2p_disconnect"
    P2P_STATUS = "p2p_status"

    # ⭐ KEY ROTATION
    KEY_ROTATE_REQUEST = "key_rotate_request"   # master → worker
    KEY_ROTATE_NEW = "key_rotate_new"           # worker → master (new pubkey)
    KEY_ROTATE_ACK = "key_rotate_ack"           # master → worker (own new pubkey)
    KEY_ROTATE_DONE = "key_rotate_done"         # confirm


MAX_PACKET = 16 * 1024 * 1024
CHUNK_SIZE = 512 * 1024


def pack_message(channel, msg_type, header=None, body=b""):
    header = dict(header or {})
    header["type"] = msg_type
    header_json = json.dumps(header, ensure_ascii=False).encode()
    plaintext = struct.pack(">I", len(header_json)) + header_json + body
    ciphertext = channel.encrypt(plaintext)
    return struct.pack(">I", len(ciphertext)) + ciphertext


async def read_message(reader, channel):
    length_bytes = await reader.readexactly(4)
    length = struct.unpack(">I", length_bytes)[0]
    if length > MAX_PACKET:
        raise ValueError(f"Packet too large: {length}")
    ciphertext = await reader.readexactly(length)
    plaintext = channel.decrypt(ciphertext)
    header_len = struct.unpack(">I", plaintext[:4])[0]
    header_json = plaintext[4:4 + header_len]
    body = plaintext[4 + header_len:]
    header = json.loads(header_json)
    msg_type = header.pop("type", "")
    return msg_type, header, body


async def write_message(writer, channel, msg_type, header=None, body=b""):
    packet = pack_message(channel, msg_type, header, body)
    writer.write(packet)
    await writer.drain()


async def send_big_file(writer, channel, prefix, filename, data, extra=None):
    extra = extra or {}
    sha = hashlib.sha256(data).hexdigest()
    total = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
    await write_message(writer, channel, f"{prefix}_start", {
        "filename": filename, "size": len(data),
        "sha256": sha, "total_chunks": total, **extra,
    })
    for idx in range(total):
        chunk = data[idx * CHUNK_SIZE:(idx + 1) * CHUNK_SIZE]
        await write_message(writer, channel, f"{prefix}_chunk", {
            "filename": filename, "idx": idx, "size": len(chunk),
        }, body=chunk)
    await write_message(writer, channel, f"{prefix}_done", {
        "filename": filename, "sha256": sha,
    })


class FileReceiver:
    def __init__(self, path):
        from pathlib import Path
        self.path = Path(path)
        self.buffer = bytearray()
        self.expected_sha = None
        self.received = 0

    def start(self, header):
        self.buffer.clear()
        self.expected_sha = header["sha256"]
        self.received = 0

    def chunk(self, header, body):
        self.buffer.extend(body)
        self.received += 1

    def finish(self, header):
        actual = hashlib.sha256(self.buffer).hexdigest()
        if actual != self.expected_sha:
            raise ValueError("SHA mismatch")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(bytes(self.buffer))
        return len(self.buffer)