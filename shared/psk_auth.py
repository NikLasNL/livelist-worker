"""
shared/psk_auth.py — PSK auth с auto-rotation.

Формат пакета:
  MAGIC(4) | VER(1) | TYPE(1) | EPH_PUB(32) | NONCE(24) | CT_LEN(2) | CT+tag

Установка:
  pip install pynacl
"""

import hashlib
import hmac
import os
import struct
import time
from typing import Optional

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as _aead_enc,
    crypto_aead_xchacha20poly1305_ietf_decrypt as _aead_dec,
)
from nacl.exceptions import CryptoError


# ─── Константы ────────────────────────────────────────────────────
MAGIC = b"LLPS"
VERSION = 0x01
TYPE_HELLO = 0x01
TYPE_REPLY = 0x02
TYPE_ACK = 0x03

EPH_LEN = 32
NONCE_LEN = 24
TAG_LEN = 16
HEADER_LEN = 4 + 1 + 1 + EPH_LEN + NONCE_LEN + 2   # = 64

MAX_AGE = 30          # сек — отклоняем старые пакеты
MAX_PACKET = 4096


class PSKError(Exception):
    pass


# ─── Crypto helpers ───────────────────────────────────────────────

def derive_key_from_password(password: str) -> bytes:
    """Сырой ключ из пароля (для bootstrap)."""
    return hashlib.sha256(
        b"livelist-psk-v1:" + password.encode()
    ).digest()


def derive_key_from_dh(shared_secret: bytes, context: bytes) -> bytes:
    """Ключ из ECDH-секрета + контекста (nonce'ы)."""
    prk = hmac.new(b"\x00" * 32, shared_secret, hashlib.sha256).digest()
    return hmac.new(prk, b"livelist-dh-v1:" + context + b"\x01",
                     hashlib.sha256).digest()


def x25519_pubkey_from_priv(priv: bytes) -> bytes:
    from nacl.bindings import crypto_scalarmult_base
    return crypto_scalarmult_base(priv)


def x25519_dh(priv: bytes, peer_pub: bytes) -> bytes:
    from nacl.bindings import crypto_scalarmult
    return crypto_scalarmult(priv, peer_pub)


def generate_x25519_keypair() -> tuple:
    priv = os.urandom(32)
    pub = x25519_pubkey_from_priv(priv)
    return priv, pub


# ─── Pack / unpack ────────────────────────────────────────────────

def pack_packet(msg_type: int, eph_pub: bytes, nonce: bytes,
                 key: bytes, plaintext: bytes) -> bytes:
    """
    Собрать пакет.
    key — 32 байта, используется для AEAD.
    """
    if len(eph_pub) != EPH_LEN:
        raise PSKError("Bad eph_pub length")
    if len(nonce) != NONCE_LEN:
        raise PSKError("Bad nonce length")
    if len(key) != 32:
        raise PSKError("Bad key length")

    # AAD = header без ciphertext
    header_prefix = (
        MAGIC
        + bytes([VERSION, msg_type])
        + eph_pub
        + nonce
    )

    # Первый расчёт — только чтобы узнать длину
    ct_tmp = _aead_enc(plaintext, header_prefix + b"\x00\x00",
                        nonce, key)

    ct_len_bytes = struct.pack(">H", len(ct_tmp))
    aad = header_prefix + ct_len_bytes

    ciphertext = _aead_enc(plaintext, aad, nonce, key)

    return aad + ciphertext


def unpack_packet(data: bytes) -> dict:
    """
    Разобрать пакет БЕЗ дешифровки.
    Возвращает: {type, eph_pub, nonce, ct_len, ciphertext, aad, raw}
    """
    if len(data) < HEADER_LEN:
        raise PSKError(f"Packet too short: {len(data)}")

    if data[:4] != MAGIC:
        raise PSKError("Bad magic")

    ver = data[4]
    if ver != VERSION:
        raise PSKError(f"Bad version: {ver}")

    msg_type = data[5]
    eph_pub = data[6:6 + EPH_LEN]
    nonce = data[6 + EPH_LEN:6 + EPH_LEN + NONCE_LEN]

    ct_len_off = 6 + EPH_LEN + NONCE_LEN
    ct_len = struct.unpack(">H", data[ct_len_off:ct_len_off + 2])[0]

    if len(data) < HEADER_LEN + ct_len:
        raise PSKError(f"Truncated: {len(data)} < {HEADER_LEN + ct_len}")

    aad = data[:HEADER_LEN]
    ciphertext = data[HEADER_LEN:HEADER_LEN + ct_len]

    return {
        "type": msg_type,
        "eph_pub": eph_pub,
        "nonce": nonce,
        "ct_len": ct_len,
        "ciphertext": ciphertext,
        "aad": aad,
    }


def decrypt_packet(parsed: dict, key: bytes) -> bytes:
    """Дешифровать ciphertext с заданным ключом."""
    try:
        plaintext = _aead_dec(
            parsed["ciphertext"], parsed["aad"],
            parsed["nonce"], key,
        )
    except CryptoError as e:
        raise PSKError(f"Decrypt failed: {e}")

    if len(plaintext) < 8:
        raise PSKError("Plaintext too short")

    ts = int.from_bytes(plaintext[:8], "big")
    age = abs(time.time() - ts)
    if age > MAX_AGE:
        raise PSKError(f"Stale packet: age={age:.1f}s")

    return plaintext[8:]