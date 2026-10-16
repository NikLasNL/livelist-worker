"""
shared/directory.py — справочник активных нод.

Хранит информацию о зарегистрированных воркерах:
  - сертификат
  - capabilities (can_relay, wg_addr, hostname, public_ip)
  - timestamps
"""

import time
from typing import Optional


class Directory:
    def __init__(self):
        # pubkey_hex → {cert, addr, connected_at, last_seen, capabilities}
        self.nodes = {}

    # ═════════════════════════════════════════════════════════════════
    # Registration
    # ═════════════════════════════════════════════════════════════════

    def register(self, cert: dict, addr: tuple) -> None:
        """Зарегистрировать воркер по сертификату."""
        if not cert or not cert.get("pubkey"):
            return

        pub = cert["pubkey"]
        self.nodes[pub] = {
            "cert": cert,
            "addr": addr,
            "connected_at": time.time(),
            "last_seen": time.time(),
            "capabilities": {
                "can_relay": cert.get("can_relay", False),
                "wg_addr": cert.get("wg_addr", ""),
                "hostname": cert.get("hostname", ""),
                "public_ip": cert.get("public_ip", ""),
            },
        }

    def unregister(self, pubkey_hex: str) -> None:
        """Убрать воркер из справочника."""
        self.nodes.pop(pubkey_hex, None)

    def update_seen(self, pubkey_hex: str) -> None:
        """Обновить timestamp последней активности."""
        if pubkey_hex in self.nodes:
            self.nodes[pubkey_hex]["last_seen"] = time.time()

    # ═════════════════════════════════════════════════════════════════
    # Queries
    # ═════════════════════════════════════════════════════════════════

    def list_all(self) -> list:
        """Все ноды."""
        return [
            {
                "cert": n["cert"],
                "capabilities": n["capabilities"],
                "connected_at": n["connected_at"],
                "last_seen": n["last_seen"],
            }
            for n in self.nodes.values()
        ]

    def list_relays(self) -> list:
        """Только те, кто может быть relay."""
        return [
            {
                "cert": n["cert"],
                "capabilities": n["capabilities"],
            }
            for n in self.nodes.values()
            if n["capabilities"].get("can_relay", False)
        ]

    def get(self, pubkey_hex: str) -> Optional[dict]:
        """Получить сертификат по pubkey."""
        n = self.nodes.get(pubkey_hex)
        return n["cert"] if n else None

    def get_capabilities(self, pubkey_hex: str) -> Optional[dict]:
        """Получить capabilities по pubkey."""
        n = self.nodes.get(pubkey_hex)
        return n["capabilities"] if n else None

    def count(self) -> int:
        """Количество нод."""
        return len(self.nodes)

    def count_relays(self) -> int:
        """Количество relay-нод."""
        return sum(
            1 for n in self.nodes.values()
            if n["capabilities"].get("can_relay", False)
        )