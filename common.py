#!/usr/bin/env python3
"""
common.py — общие утилиты для LiveList
  • VPNGuardClient — клиент control-порта :9055
  • TelegramNotifier — уведомления
  • ensure_vpn() — гарантирует, что VPN работает
  • retry_with_vpn() — retry HTTP с ротацией при ошибке
"""

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Optional, Callable, Any

import aiohttp


# ═════════════════════════════════════════════════════════════════════
# VPN Guard Client
# ═════════════════════════════════════════════════════════════════════

class VPNGuardClient:
    def __init__(self, host: str = "127.0.0.1",
                 port: int = 9055, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.available = True
        self.rotations_done = 0

    async def _send(self, cmd: str) -> Optional[str]:
        if not self.available:
            return None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=10
            )
            writer.write((cmd + "\n").encode())
            await writer.drain()
            data = await asyncio.wait_for(
                reader.readline(), timeout=self.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return data.decode().strip()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def ping(self) -> bool:
        r = await self._send("PING")
        if r == "PONG":
            self.available = True
            return True
        self.available = False
        return False

    async def status(self) -> dict:
        r = await self._send("STATUS")
        if r and r.startswith("STATUS "):
            try:
                return json.loads(r[7:])
            except json.JSONDecodeError:
                return {}
        return {}

    async def rotate(self) -> dict:
        r = await self._send("ROTATE")
        if r and r.startswith("OK "):
            try:
                status = json.loads(r[3:])
                self.rotations_done += 1
                return status
            except json.JSONDecodeError:
                return {}
        return {}

    async def wait_for_up(self, timeout: int = 300) -> bool:
        """Ждать, пока VPN перестанет быть в состоянии rotating."""
        start = time.time()
        while time.time() - start < timeout:
            st = await self.status()
            state = st.get("state", "unknown")
            if state == "up":
                return True
            if state == "stopped":
                return False
            await asyncio.sleep(5)
        return False

    async def ensure_vpn(self, notifier: "TelegramNotifier" = None) -> bool:
        """
        Проверить, что VPN работает. Если нет:
          1. Запросить ROTATE
          2. Ждать пока state=up (до 5 мин)
        """
        # PING
        if not await self.ping():
            if notifier:
                await notifier.send(
                    "⚠️ <b>VPN Guard недоступен</b>\n"
                    "Проверь, что <code>~/vpn_guard_ctl.py</code> запущен"
                )
            return False

        st = await self.status()
        state = st.get("state", "unknown")
        ip = st.get("ip", "?")

        if state == "up":
            return True

        # Не up → нужен rotate
        if notifier:
            await notifier.send(
                f"🔄 <b>VPN не работает</b> (state={state})\n"
                f"Запрашиваю ROTATE...\n"
                f"Старый IP: <code>{ip}</code>"
            )

        await self.rotate()
        ok = await self.wait_for_up(timeout=300)

        if ok:
            st = await self.status()
            new_ip = st.get("ip", "?")
            if notifier:
                await notifier.send(
                    f"✅ <b>VPN восстановлен</b>\n"
                    f"Новый IP: <code>{new_ip}</code>\n"
                    f"Ротаций: {self.rotations_done}"
                )
            return True
        else:
            if notifier:
                await notifier.send(
                    "❌ <b>VPN не восстановился</b> за 5 минут\n"
                    "Проверь: <code>~/logs/vpn_guard.log</code>"
                )
            return False


# ═════════════════════════════════════════════════════════════════════
# Telegram Notifier
# ═════════════════════════════════════════════════════════════════════

class TelegramNotifier:
    def __init__(self, token: Optional[str] = None,
                 chat_id: Optional[str] = None,
                 enabled: bool = True):
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID")
        self.enabled = enabled and bool(self.token) and bool(self.chat_id)
        self._last_sent = 0.0
        self._min_interval = 1.0    # анти-спам
        self._queue_count = 0

    async def send(self, text: str) -> bool:
        if not self.enabled:
            return False

        # Анти-спам
        now = time.time()
        if now - self._last_sent < self._min_interval:
            await asyncio.sleep(self._min_interval - (now - self._last_sent))
        self._last_sent = time.time()

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    url,
                    json={
                        "chat_id": self.chat_id,
                        "text": text,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True,
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    return r.status == 200
        except Exception:
            return False

    async def step(self, phase: str, message: str):
        """Уведомление о шаге."""
        await self.send(f"📌 <b>{phase}</b>\n{message}")

    async def progress(self, phase: str, current: int, total: int,
                       extra: str = ""):
        """Прогресс (каждые 10%)."""
        if total <= 0:
            return
        pct = int(100 * current / total)
        if pct % 10 != 0 and current != total:
            return
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        text = (
            f"📊 <b>{phase}</b>\n"
            f"<code>{bar}</code> {pct}%\n"
            f"{current}/{total}"
        )
        if extra:
            text += f"\n{extra}"
        await self.send(text)

    async def error(self, where: str, err: str):
        await self.send(f"❌ <b>Ошибка: {where}</b>\n<code>{err[:300]}</code>")

    async def success(self, what: str, details: str = ""):
        text = f"✅ <b>{what}</b>"
        if details:
            text += f"\n{details}"
        await self.send(text)


# ═════════════════════════════════════════════════════════════════════
# Retry с VPN rotation
# ═════════════════════════════════════════════════════════════════════

async def retry_with_vpn(
    func: Callable,
    *args,
    vpn: VPNGuardClient,
    notifier: TelegramNotifier,
    context: str = "request",
    max_retries: int = 3,
    **kwargs,
) -> Any:
    """
    Вызывает func(*args, **kwargs).
    При сетевой ошибке:
      1. Уведомляет в Telegram
      2. Проверяет/ротирует VPN
      3. Повторяет запрос
    """
    for attempt in range(max_retries):
        try:
            result = await func(*args, **kwargs)
            if result is not None:
                return result
            # None = ошибка внутри
            raise RuntimeError(f"{context} вернул None")

        except (aiohttp.ClientConnectorError,
                aiohttp.ClientError,
                asyncio.TimeoutError,
                OSError) as e:
            err_name = type(e).__name__
            err_msg = str(e)[:200]

            await notifier.send(
                f"⚠️ <b>Сетевая ошибка</b> ({context})\n"
                f"<code>{err_name}: {err_msg}</code>\n"
                f"Попытка {attempt + 1}/{max_retries}"
            )

            # Проверить/переключить VPN
            if not await vpn.ensure_vpn(notifier):
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(30)
                continue

            # Пауза перед retry
            await asyncio.sleep(5)
            continue

    return None


# ═════════════════════════════════════════════════════════════════════
# env loader
# ═════════════════════════════════════════════════════════════════════

def load_env(path: Path):
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k not in os.environ:
            os.environ[k] = v


def load_all_env():
    load_env(Path.home() / ".telegram.env")
    load_env(Path.home() / ".cve_explore.env")
