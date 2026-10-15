"""
shared/bootstrap.py — токены первичной регистрации.
"""

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path


class BootstrapManager:
    def __init__(self, path: Path):
        self.path = path
        self.tokens = {}
        self._load()

    def _load(self):
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            self.tokens = data.get("tokens", {})
        except Exception:
            pass

    def _save(self):
        self.path.write_text(json.dumps({
            "tokens": self.tokens,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2))
        self.path.chmod(0o600)

    def generate(self, uses: int = 1, ttl_hours: int = 24,
                  note: str = "") -> str:
        raw = secrets.token_hex(10).upper()
        token = "-".join([raw[i:i+4] for i in range(0, 20, 4)])
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        expires = (datetime.now(timezone.utc)
                    + timedelta(hours=ttl_hours)).isoformat()

        self.tokens[token_hash] = {
            "uses_left": uses,
            "expires": expires,
            "note": note,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()
        return token

    def consume(self, token: str) -> bool:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        info = self.tokens.get(token_hash)
        if not info:
            return False

        expires = datetime.fromisoformat(info["expires"])
        if expires < datetime.now(timezone.utc):
            del self.tokens[token_hash]
            self._save()
            return False

        if info["uses_left"] <= 0:
            return False

        info["uses_left"] -= 1
        if info["uses_left"] == 0:
            del self.tokens[token_hash]
        self._save()
        return True

    def list_tokens(self) -> list:
        return [{
            "hash": h[:16] + "...",
            "uses_left": info["uses_left"],
            "expires": info["expires"][:19],
            "note": info.get("note", ""),
        } for h, info in self.tokens.items()]