"""
shared/directory.py — справочник активных нод.
"""

import time
from typing import Optional


class Directory:
    def __init__(self):
        self.nodes = {}   # pubkey_hex → info

    def register(self, cert: dict, addr: tuple):
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

    def unregister(self, pubkey_hex: str):
        self.nodes.pop(pubkey_hex, None)

    def update_seen(self, pubkey_hex: str):
        if pubkey_hex in self.nodes:
            self.nodes[pubkey_hex]["last_seen"] = time.time()

    def list_all(self) -> list:
        return [{
            "cert": n["cert"],
            "capabilities": n["capabilities"],
            "connected_at": n["connected_at"],
            "last_seen": n["last_seen"],
        } for n in self.nodes.values()]

    def list_relays(self) -> list:
        return [{
            "cert": n["cert"],
            "capabilities": n["capabilities"],
        } for n in self.nodes.values()
              if n["capabilities"]["can_relay"]]

    def get(self, pubkey_hex: str) -> Optional[dict]:
        n = self.nodes.get(pubkey_hex)
        return n["cert"] if n else None

    def count(self) -> int:
        return len(self.nodes)