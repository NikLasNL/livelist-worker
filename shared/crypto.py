"""
shared/crypto.py — X25519 + ChaCha20-Poly1305 + HKDF + HMAC-2FA + Key Rotation
"""

import os
import struct
import hashlib
import hmac
from pathlib import Path

from nacl import bindings
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random


def generate_keypair():
    private = nacl_random(32)
    public = bindings.crypto_scalarmult_base(private)
    return private, public


def dh(private, peer_public):
    return bindings.crypto_scalarmult(private, peer_public)


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length=64):
    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]


def derive_session_keys(shared_secret, info=b"livelist-v3"):
    salt = b"\x00" * 32
    prk = hkdf_extract(salt, shared_secret)
    keys = hkdf_expand(prk, info, 64)
    return keys[:32], keys[32:]


class EncryptedChannel:
    def __init__(self, send_key, recv_key):
        self.send_box = SecretBox(send_key)
        self.recv_box = SecretBox(recv_key)
        self.send_counter = 0
        self.recv_counter = 0

    def _nonce(self, counter):
        return b"\x00\x00\x00\x00" + struct.pack(">Q", counter)

    def encrypt(self, plaintext):
        nonce = self._nonce(self.send_counter)
        self.send_counter += 1
        return self.send_box.encrypt(plaintext, nonce).ciphertext

    def decrypt(self, ciphertext):
        nonce = self._nonce(self.recv_counter)
        self.recv_counter += 1
        return self.recv_box.decrypt(ciphertext, nonce)


def compute_2fa_response(shared_secret, nonce, password_hash):
    key = hashlib.sha256(shared_secret + password_hash.encode()).digest()
    return hmac.new(key, nonce, hashlib.sha256).digest()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ═════════════════════════════════════════════════════════════════════
# Handshake
# ═════════════════════════════════════════════════════════════════════

class Handshake:
    @staticmethod
    async def client_handshake(reader, writer,
                                my_static_priv, server_static_pub,
                                password):
        eph_priv, eph_pub = generate_keypair()
        my_static_pub = bindings.crypto_scalarmult_base(my_static_priv)

        writer.write(eph_pub + my_static_pub)
        await writer.drain()

        server_eph_pub = await reader.readexactly(32)
        nonce = await reader.readexactly(32)

        dh1 = dh(eph_priv, server_eph_pub)
        dh2 = dh(my_static_priv, server_eph_pub)
        dh3 = dh(eph_priv, server_static_pub)
        shared = dh1 + dh2 + dh3

        c2s_key, s2c_key = derive_session_keys(shared)
        channel = EncryptedChannel(send_key=c2s_key, recv_key=s2c_key)

        pwd_hash = hash_password(password)
        response = compute_2fa_response(shared, nonce, pwd_hash)
        writer.write(channel.encrypt(response))
        await writer.drain()

        welcome_len_bytes = await reader.readexactly(4)
        welcome_len = struct.unpack(">I", welcome_len_bytes)[0]
        welcome_ct = await reader.readexactly(welcome_len)
        welcome = channel.decrypt(welcome_ct)

        if welcome != b"welcome":
            raise PermissionError("2FA failed")

        return channel

    @staticmethod
    async def server_handshake(reader, writer,
                                my_static_priv, allowed_clients,
                                password,
                                also_accept=None):
        """
        also_accept — дополнительный whitelist (bootstrap keys).
        """
        client_eph_pub = await reader.readexactly(32)
        client_static_pub = await reader.readexactly(32)

        allow = set(allowed_clients)
        if also_accept:
            allow |= set(also_accept)

        if client_static_pub not in allow:
            raise PermissionError(
                f"Unknown client: {client_static_pub.hex()[:16]}"
            )

        eph_priv, eph_pub = generate_keypair()
        nonce = nacl_random(32)

        writer.write(eph_pub + nonce)
        await writer.drain()

        dh1 = dh(eph_priv, client_eph_pub)
        dh2 = dh(eph_priv, client_static_pub)
        dh3 = dh(my_static_priv, client_eph_pub)
        shared = dh1 + dh2 + dh3

        c2s_key, s2c_key = derive_session_keys(shared)
        channel = EncryptedChannel(send_key=s2c_key, recv_key=c2s_key)

        resp_len_bytes = await reader.readexactly(4)
        resp_len = struct.unpack(">I", resp_len_bytes)[0]
        resp_ct = await reader.readexactly(resp_len)
        resp = channel.decrypt(resp_ct)

        pwd_hash = hash_password(password)
        expected = compute_2fa_response(shared, nonce, pwd_hash)

        if not hmac.compare_digest(resp, expected):
            raise PermissionError("2FA failed")

        writer.write(channel.encrypt(b"welcome"))
        await writer.drain()

        return channel, client_static_pub


# ═════════════════════════════════════════════════════════════════════
# Key rotation helpers
# ═════════════════════════════════════════════════════════════════════

def rotate_keypair(current_path: Path, backup_dir: Path = None):
    """
    Сгенерировать новую пару, сохранить текущую в backup.
    Возвращает (old_priv, old_pub, new_priv, new_pub).
    """
    old_priv, old_pub = load_keypair(current_path)

    if backup_dir:
        backup_dir.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        save_keypair(backup_dir / f"key_{ts}.json", old_priv, old_pub)

    new_priv, new_pub = generate_keypair()
    save_keypair(current_path, new_priv, new_pub)
    return old_priv, old_pub, new_priv, new_pub


# ═════════════════════════════════════════════════════════════════════
# Key storage
# ═════════════════════════════════════════════════════════════════════

def save_keypair(path, private, public):
    path.write_text(f"{private.hex()}\n{public.hex()}\n")
    path.chmod(0o600)


def load_keypair(path):
    lines = path.read_text().splitlines()
    return bytes.fromhex(lines[0]), bytes.fromhex(lines[1])