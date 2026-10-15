"""
shared/module_pack.py — упаковка/распаковка Python-модулей

Формат пакета:
    [MAGIC 4B "LLMP"]
    [header_len: uint32 big-endian]
    [header: JSON utf-8]
    [payload: XOR(source_bytes, xor_key)]

Header:
    {
        "name":          "spider",
        "version":       1,
        "size":          12345,
        "sha256":        "...",
        "xor_key_hash":  "...",   # sha256(xor_key)[:16]
        "packed_at":     "2026-10-15T..."
    }

XOR-ключ — 32 байта, деривится из shared_secret канала + имени модуля.
Одинаков на обеих сторонах.
"""

import hashlib
import hmac
import json
import struct
from datetime import datetime, timezone
from typing import Tuple

MAGIC = b"LLMP"
VERSION = 1
MAX_HEADER = 65536


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR с циклическим ключом."""
    if not key:
        raise ValueError("Empty XOR key")
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def derive_xor_key(shared_secret: bytes, module_name: str) -> bytes:
    """XOR-ключ из shared_secret канала + имени модуля."""
    if not shared_secret:
        raise ValueError("Empty shared_secret")
    salt = b"\x00" * 32
    prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()
    info = b"module-xor-v1:" + module_name.encode("utf-8")
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def pack_module(name: str, source: bytes, xor_key: bytes) -> bytes:
    """Упаковать .py файл в бинарный пакет."""
    if not name:
        raise ValueError("Empty module name")
    if not xor_key:
        raise ValueError("Empty xor key")
    if not isinstance(source, (bytes, bytearray)):
        raise TypeError("source must be bytes")

    source = bytes(source)
    sha256 = hashlib.sha256(source).hexdigest()
    xor_key_hash = hashlib.sha256(xor_key).hexdigest()[:16]

    header = {
        "name": name,
        "version": VERSION,
        "size": len(source),
        "sha256": sha256,
        "xor_key_hash": xor_key_hash,
        "packed_at": datetime.now(timezone.utc).isoformat(),
    }
    header_json = json.dumps(header, ensure_ascii=False).encode("utf-8")
    header_len = struct.pack(">I", len(header_json))
    payload = xor_bytes(source, xor_key)

    return MAGIC + header_len + header_json + payload


def unpack_module(package: bytes, xor_key: bytes) -> Tuple[str, bytes]:
    """
    Распаковать пакет.
    Возвращает (name, source_bytes).
    Бросает ValueError при несоответствии.
    """
    if len(package) < 8:
        raise ValueError("Package too short")
    if package[:4] != MAGIC:
        raise ValueError(f"Bad magic: {package[:4]!r}")

    header_len = struct.unpack(">I", package[4:8])[0]
    if header_len > MAX_HEADER:
        raise ValueError(f"Header too large: {header_len}")

    header_end = 8 + header_len
    if len(package) < header_end:
        raise ValueError("Truncated header")

    header_json = package[8:header_end]
    payload = package[header_end:]

    try:
        header = json.loads(header_json.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Bad header JSON: {e}")

    if header.get("version") != VERSION:
        raise ValueError(f"Unsupported version: {header.get('version')}")

    name = header.get("name")
    if not name:
        raise ValueError("No module name in header")

    # XOR key check
    expected_key_hash = hashlib.sha256(xor_key).hexdigest()[:16]
    if header.get("xor_key_hash") != expected_key_hash:
        raise ValueError(
            f"XOR key mismatch "
            f"({header.get('xor_key_hash')} != {expected_key_hash})"
        )

    # XOR decrypt
    source = xor_bytes(payload, xor_key)

    # Size check
    if len(source) != header.get("size"):
        raise ValueError(
            f"Size mismatch: {len(source)} != {header.get('size')}"
        )

    # SHA256 check
    actual_sha = hashlib.sha256(source).hexdigest()
    if actual_sha != header.get("sha256"):
        raise ValueError(
            f"SHA256 mismatch: {actual_sha} != {header.get('sha256')}"
        )

    return name, source