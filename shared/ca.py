"""
shared/ca.py — Ed25519 Certificate Authority для LiveList.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nacl import signing
from nacl.exceptions import BadSignatureError


def generate_ca_keypair():
    private = signing.SigningKey.generate()
    public = private.verify_key
    return private.encode(), public.encode()


def save_ca_keypair(path: Path, private: bytes, public: bytes):
    path.write_text(f"{private.hex()}\n{public.hex()}\n")
    path.chmod(0o600)


def load_ca_keypair(path: Path):
    lines = path.read_text().splitlines()
    return bytes.fromhex(lines[0]), bytes.fromhex(lines[1])


def _cert_canonical(cert: dict) -> bytes:
    data = {k: v for k, v in cert.items() if k != "signature"}
    return json.dumps(data, sort_keys=True,
                       separators=(',', ':')).encode()


def issue_certificate(ca_private: bytes, worker_pubkey_hex: str,
                       wg_addr: str, hostname: str,
                       public_ip: str = "", can_relay: bool = False,
                       ttl_days: int = 365) -> dict:
    sk = signing.SigningKey(ca_private)
    now = datetime.now(timezone.utc)

    cert = {
        "pubkey": worker_pubkey_hex,
        "wg_addr": wg_addr,
        "hostname": hostname,
        "public_ip": public_ip,
        "can_relay": bool(can_relay),
        "issued_at": now.isoformat(),
        "expires": (now + timedelta(days=ttl_days)).isoformat(),
    }

    sig = sk.sign(_cert_canonical(cert)).signature
    cert["signature"] = sig.hex()
    return cert


def verify_certificate(ca_public: bytes, cert: dict) -> bool:
    try:
        vk = signing.VerifyKey(ca_public)
        sig = bytes.fromhex(cert["signature"])
        vk.verify(_cert_canonical(cert), sig)

        expires = datetime.fromisoformat(cert["expires"])
        if expires < datetime.now(timezone.utc):
            return False
        return True
    except (BadSignatureError, KeyError, ValueError):
        return False


def cert_fingerprint(cert: dict) -> str:
    return hashlib.sha256(_cert_canonical(cert)).hexdigest()[:16]