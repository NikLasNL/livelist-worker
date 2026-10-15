#!/usr/bin/env python3
"""
cve_explore.py v6 — FINAL

Возможности:
  • Дневное кэширование через fetch_history
  • Auto-миграция схемы БД (ALTER TABLE для недостающих колонок)
  • Правильный парсер API (hits внутри ключа-запроса)
  • VPN retry с auto-rotation
  • Telegram-уведомления на каждом шаге
  • Debug режим с полной диагностикой
  • CLI: collect, stats, clear-cache, debug, search, cve, pocs и т.д.

Использование:
  python3 cve_explore.py collect              # проверка кэша
  python3 cve_explore.py collect --force      # принудительно
  python3 cve_explore.py stats                # статистика БД
  python3 cve_explore.py clear-cache          # очистить историю
  python3 cve_explore.py debug                # диагностика API
  python3 cve_explore.py search apache        # поиск
"""

import asyncio
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, date, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import aiohttp

from common import (
    VPNGuardClient, TelegramNotifier, retry_with_vpn,
    load_all_env,
)


BASE_URL = "https://cve-explore.com"
API_PREFIX = "/api/v1"
LIVELIST_DB = "livelist.db"


# ═════════════════════════════════════════════════════════════════════
# SQLite — ЕДИНАЯ СХЕМА
# ═════════════════════════════════════════════════════════════════════

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS fetch_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fetch_date TEXT NOT NULL,
    source TEXT NOT NULL,
    last_fetch TEXT NOT NULL,
    vendors_count INTEGER DEFAULT 0,
    products_count INTEGER DEFAULT 0,
    cves_count INTEGER DEFAULT 0,
    success INTEGER DEFAULT 1,
    note TEXT,
    UNIQUE(fetch_date, source)
);
CREATE INDEX IF NOT EXISTS idx_fetch_date ON fetch_history(fetch_date);

CREATE TABLE IF NOT EXISTS vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    cve_count INTEGER DEFAULT 0,
    fetched_at TEXT
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT,
    name TEXT,
    cve_count INTEGER DEFAULT 0,
    fetched_at TEXT,
    UNIQUE(vendor, name)
);

CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE,
    has_poc INTEGER DEFAULT 0,
    poc_count INTEGER DEFAULT 0,
    description TEXT,
    cvss REAL,
    severity TEXT,
    vendor TEXT,
    product TEXT,
    published_at TEXT,
    modified_at TEXT,
    kev_added_at TEXT,
    kev_ransomware INTEGER DEFAULT 0,
    metasploit_modules INTEGER DEFAULT 0,
    source TEXT,
    fetched_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_cves_has_poc ON cves(has_poc);
CREATE INDEX IF NOT EXISTS idx_cves_vendor ON cves(vendor);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev_added_at);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 0,
    country TEXT,
    city TEXT,
    query TEXT,
    cve_id TEXT,
    source TEXT,
    status INTEGER,
    server TEXT,
    title TEXT,
    shodan_vulns TEXT,
    first_seen TEXT,
    last_seen TEXT,
    UNIQUE(ip, port)
);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_hosts_cve ON hosts(cve_id);
CREATE INDEX IF NOT EXISTS idx_hosts_country ON hosts(country);
CREATE INDEX IF NOT EXISTS idx_hosts_city ON hosts(city);

CREATE TABLE IF NOT EXISTS nuclei_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    port INTEGER,
    template_id TEXT,
    cve_id TEXT,
    severity TEXT,
    name TEXT,
    matched_at TEXT,
    found_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_nuclei_ip ON nuclei_findings(ip);
CREATE INDEX IF NOT EXISTS idx_nuclei_cve ON nuclei_findings(cve_id);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT,
    finished_at TEXT,
    query TEXT,
    total_ips INTEGER,
    alive_count INTEGER,
    cve_count INTEGER,
    nuclei_count INTEGER
);
"""


# ═════════════════════════════════════════════════════════════════════
# Auto-migration — добавление недостающих колонок
# ═════════════════════════════════════════════════════════════════════

def _migrate_schema(conn: sqlite3.Connection):
    """
    Добавляет недостающие колонки в существующие таблицы.
    SQLite CREATE TABLE IF NOT EXISTS не обновляет схему.
    """
    migrations = [
        # cves
        ("cves", "severity", "TEXT"),
        ("cves", "cvss", "REAL"),
        ("cves", "vendor", "TEXT"),
        ("cves", "product", "TEXT"),
        ("cves", "published_at", "TEXT"),
        ("cves", "modified_at", "TEXT"),
        ("cves", "kev_added_at", "TEXT"),
        ("cves", "kev_ransomware", "INTEGER DEFAULT 0"),
        ("cves", "metasploit_modules", "INTEGER DEFAULT 0"),
        ("cves", "source", "TEXT"),
        ("cves", "fetched_at", "TEXT"),
        ("cves", "poc_count", "INTEGER DEFAULT 0"),
        ("cves", "has_poc", "INTEGER DEFAULT 0"),
        ("cves", "description", "TEXT"),
        # hosts
        ("hosts", "country", "TEXT"),
        ("hosts", "city", "TEXT"),
        ("hosts", "cve_id", "TEXT"),
        ("hosts", "shodan_vulns", "TEXT"),
        ("hosts", "first_seen", "TEXT"),
        ("hosts", "last_seen", "TEXT"),
        ("hosts", "status", "INTEGER"),
        ("hosts", "server", "TEXT"),
        ("hosts", "title", "TEXT"),
        ("hosts", "query", "TEXT"),
        ("hosts", "source", "TEXT"),
        # nuclei_findings
        ("nuclei_findings", "severity", "TEXT"),
        ("nuclei_findings", "cve_id", "TEXT"),
        ("nuclei_findings", "template_id", "TEXT"),
        ("nuclei_findings", "matched_at", "TEXT"),
        ("nuclei_findings", "name", "TEXT"),
    ]

    migrated = 0
    for table, column, coltype in migrations:
        try:
            cur = conn.execute(f"PRAGMA table_info({table})")
            existing = {row[1] for row in cur.fetchall()}
            if not existing:
                # Таблица ещё не существует, будет создана через schema
                continue
            if column not in existing:
                print(f"[migrate] + {table}.{column} ({coltype})")
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"
                )
                conn.commit()
                migrated += 1
        except sqlite3.Error as e:
            print(f"[migrate] skip {table}.{column}: {e}")

    if migrated:
        print(f"[migrate] ✓ Добавлено колонок: {migrated}")


# ═════════════════════════════════════════════════════════════════════
# Хелперы
# ═════════════════════════════════════════════════════════════════════

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> str:
    return date.today().isoformat()


def init_db(db_path: str = LIVELIST_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript(SQLITE_SCHEMA)
    conn.commit()
    _migrate_schema(conn)
    return conn


# ═════════════════════════════════════════════════════════════════════
# Fetch history — дневной кэш
# ═════════════════════════════════════════════════════════════════════

def fetch_history_check_today(conn, source: str = "cve-explore") -> Optional[dict]:
    try:
        cur = conn.execute(
            "SELECT fetch_date, last_fetch, vendors_count, "
            "products_count, cves_count, success, note "
            "FROM fetch_history "
            "WHERE fetch_date = ? AND source = ? AND success = 1",
            (_today(), source),
        )
        row = cur.fetchone()
        if row:
            return {
                "fetch_date": row[0],
                "last_fetch": row[1],
                "vendors_count": row[2],
                "products_count": row[3],
                "cves_count": row[4],
                "success": bool(row[5]),
                "note": row[6] or "",
            }
    except sqlite3.Error as e:
        print(f"[!] fetch_history_check: {e}")
    return None


def fetch_history_record(conn, source: str = "cve-explore",
                          vendors_count=0, products_count=0,
                          cves_count=0, success=True, note=""):
    try:
        conn.execute(
            "INSERT INTO fetch_history "
            "(fetch_date, source, last_fetch, vendors_count, "
            "products_count, cves_count, success, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(fetch_date, source) DO UPDATE SET "
            "last_fetch=excluded.last_fetch, "
            "vendors_count=excluded.vendors_count, "
            "products_count=excluded.products_count, "
            "cves_count=excluded.cves_count, "
            "success=excluded.success, "
            "note=excluded.note",
            (_today(), source, _now(), vendors_count, products_count,
             cves_count, int(success), note[:500]),
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"[!] fetch_history_record: {e}")


def get_stats_from_db(conn) -> dict:
    stats = {
        "vendors": 0, "products": 0, "cves_total": 0,
        "cves_poc": 0, "cves_kev": 0, "hosts": 0, "nuclei": 0,
    }
    try:
        stats["vendors"] = conn.execute(
            "SELECT COUNT(*) FROM vendors").fetchone()[0]
        stats["products"] = conn.execute(
            "SELECT COUNT(*) FROM products").fetchone()[0]
        stats["cves_total"] = conn.execute(
            "SELECT COUNT(*) FROM cves").fetchone()[0]
        stats["cves_poc"] = conn.execute(
            "SELECT COUNT(*) FROM cves WHERE has_poc=1").fetchone()[0]
        try:
            stats["cves_kev"] = conn.execute(
                "SELECT COUNT(*) FROM cves WHERE kev_added_at IS NOT NULL "
                "AND kev_added_at != ''").fetchone()[0]
        except sqlite3.Error:
            stats["cves_kev"] = 0
        stats["hosts"] = conn.execute(
            "SELECT COUNT(*) FROM hosts").fetchone()[0]
        stats["nuclei"] = conn.execute(
            "SELECT COUNT(*) FROM nuclei_findings").fetchone()[0]
    except sqlite3.Error:
        pass
    return stats


# ═════════════════════════════════════════════════════════════════════
# DB upsert helpers
# ═════════════════════════════════════════════════════════════════════

def db_upsert_vendor(conn, name, cve_count=0):
    if not name:
        return
    try:
        conn.execute(
            "INSERT INTO vendors (name, cve_count, fetched_at) "
            "VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
            "cve_count=excluded.cve_count, fetched_at=excluded.fetched_at",
            (name, cve_count, _now()),
        )
        conn.commit()
    except sqlite3.Error:
        pass


def db_upsert_product(conn, vendor, name, cve_count=0):
    if not vendor or not name:
        return
    try:
        conn.execute(
            "INSERT INTO products (vendor, name, cve_count, fetched_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(vendor, name) DO UPDATE SET "
            "cve_count=excluded.cve_count, fetched_at=excluded.fetched_at",
            (vendor, name, cve_count, _now()),
        )
        conn.commit()
    except sqlite3.Error:
        pass


def db_upsert_cve(conn, c: dict):
    if not c.get("cve_id"):
        return
    try:
        conn.execute(
            "INSERT INTO cves (cve_id, has_poc, poc_count, description, "
            "cvss, severity, vendor, product, published_at, modified_at, "
            "kev_added_at, kev_ransomware, metasploit_modules, source, fetched_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(cve_id) DO UPDATE SET "
            "has_poc=MAX(excluded.has_poc, cves.has_poc), "
            "poc_count=MAX(excluded.poc_count, cves.poc_count), "
            "description=COALESCE(NULLIF(excluded.description,''), cves.description), "
            "cvss=COALESCE(excluded.cvss, cves.cvss), "
            "severity=COALESCE(NULLIF(excluded.severity,''), cves.severity), "
            "vendor=COALESCE(NULLIF(excluded.vendor,''), cves.vendor), "
            "product=COALESCE(NULLIF(excluded.product,''), cves.product), "
            "kev_added_at=COALESCE(excluded.kev_added_at, cves.kev_added_at), "
            "kev_ransomware=MAX(excluded.kev_ransomware, cves.kev_ransomware), "
            "metasploit_modules=MAX(excluded.metasploit_modules, cves.metasploit_modules)",
            (c.get("cve_id"), int(c.get("has_poc", 0)),
             int(c.get("poc_count", 0)),
             (c.get("description") or "")[:4000],
             c.get("cvss"),
             c.get("severity") or "",
             c.get("vendor") or "",
             c.get("product") or "",
             c.get("published_at"),
             c.get("modified_at"),
             c.get("kev_added_at"),
             int(c.get("kev_ransomware", 0)),
             int(c.get("metasploit_modules", 0)),
             c.get("source", "cve-explore"),
             _now()),
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"[!] db_upsert_cve({c.get('cve_id')}): {e}")


def db_upsert_host(conn, data: dict):
    now = _now()
    port = data.get("port") or 0
    try:
        conn.execute(
            "INSERT INTO hosts (ip, port, country, city, query, cve_id, "
            "source, status, server, title, shodan_vulns, "
            "first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip, port) DO UPDATE SET "
            "country=COALESCE(NULLIF(excluded.country,''), hosts.country), "
            "city=COALESCE(NULLIF(excluded.city,''), hosts.city), "
            "cve_id=COALESCE(NULLIF(excluded.cve_id,''), hosts.cve_id), "
            "status=COALESCE(excluded.status, hosts.status), "
            "server=COALESCE(NULLIF(excluded.server,''), hosts.server), "
            "title=COALESCE(NULLIF(excluded.title,''), hosts.title), "
            "shodan_vulns=COALESCE(NULLIF(excluded.shodan_vulns,'[]'), hosts.shodan_vulns), "
            "last_seen=excluded.last_seen",
            (data.get("ip"), port,
             data.get("country") or "",
             data.get("city") or "",
             data.get("query"),
             data.get("cve_id"),
             data.get("source"),
             data.get("status"),
             data.get("server") or "",
             data.get("title") or "",
             json.dumps(data.get("shodan_vulns", [])),
             now, now),
        )
        conn.commit()
    except sqlite3.Error:
        pass


def db_insert_nuclei(conn, f: dict):
    try:
        conn.execute(
            "INSERT INTO nuclei_findings (ip, port, template_id, cve_id, "
            "severity, name, matched_at, found_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (f.get("ip"), f.get("port"), f.get("template_id"),
             f.get("cve_id"), f.get("severity"), f.get("name"),
             f.get("matched_at"), _now()),
        )
        conn.commit()
    except sqlite3.Error:
        pass


def db_start_scan(conn, query, total_ips):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (started_at, query, total_ips) VALUES (?, ?, ?)",
        (_now(), query, total_ips),
    )
    conn.commit()
    return cur.lastrowid


def db_finish_scan(conn, scan_id, alive, cve, nuclei):
    conn.execute(
        "UPDATE scans SET finished_at=?, alive_count=?, cve_count=?, "
        "nuclei_count=? WHERE id=?",
        (_now(), alive, cve, nuclei, scan_id),
    )
    conn.commit()


# ═════════════════════════════════════════════════════════════════════
# API response parsers (real format: hits inside query key)
# ═════════════════════════════════════════════════════════════════════

def _extract_search_hits(data) -> list:
    """
    Формат /cves/search:
    {
        "<query>": {
            "facets": {...},
            "hits": [...],
            "page": 1,
            "total": N
        }
    }
    """
    if not data:
        return []
    if isinstance(data, dict) and "hits" in data \
            and isinstance(data["hits"], list):
        return data["hits"]
    if isinstance(data, dict):
        reserved = {"facets", "total", "page", "per_page",
                    "took_ms", "hits", "error", "status"}
        for key, val in data.items():
            if key in reserved:
                continue
            if isinstance(val, dict):
                hits = val.get("hits")
                if isinstance(hits, list):
                    return hits
    if isinstance(data, list):
        return data
    return []


def _extract_search_meta(data) -> dict:
    if not isinstance(data, dict):
        return {}
    reserved = {"facets", "total", "page", "per_page",
                "took_ms", "hits", "error", "status"}
    for key, val in data.items():
        if key in reserved:
            continue
        if isinstance(val, dict):
            return {
                "total": val.get("total", 0),
                "page": val.get("page", 1),
                "per_page": val.get("per_page", 20),
            }
    return {
        "total": data.get("total", 0),
        "page": data.get("page", 1),
        "per_page": data.get("per_page", 20),
    }


def _extract_generic_list(data, keys=None) -> list:
    if keys is None:
        keys = ["items", "data", "results", "vendors", "products",
                "hits", "values"]
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if isinstance(v, list):
                return v
        for k, v in data.items():
            if isinstance(v, dict):
                nested = _extract_generic_list(v, keys)
                if nested:
                    return nested
    return []


def _extract_cve_id(item) -> Optional[str]:
    if not isinstance(item, dict):
        return None
    for key in ("id", "cve_id", "cve", "cveId", "cveID", "CVE"):
        v = item.get(key)
        if v and isinstance(v, str) and v.upper().startswith("CVE-"):
            return v.upper()
    return None


def _cve_item_to_db(item: dict) -> Optional[dict]:
    if not isinstance(item, dict):
        return None
    cve_id = _extract_cve_id(item)
    if not cve_id:
        return None

    vendors = item.get("vendors") or []
    products = item.get("products") or []

    vendor_str = (", ".join(str(v) for v in vendors)
                  if isinstance(vendors, list) else str(vendors))[:500]
    product_str = (", ".join(str(p) for p in products)
                   if isinstance(products, list) else str(products))[:2000]

    return {
        "cve_id": cve_id,
        "has_poc": bool(item.get("has_poc", False)),
        "poc_count": int(item.get("poc_count", 0) or 0),
        "description": item.get("description", "") or "",
        "cvss": item.get("cvss_v3_score") or item.get("cvss"),
        "severity": item.get("cvss_v3_severity") or "",
        "vendor": vendor_str,
        "product": product_str,
        "published_at": item.get("published_at"),
        "modified_at": item.get("modified_at"),
        "kev_added_at": item.get("kev_added_at"),
        "kev_ransomware": bool(item.get("kev_known_ransomware", False)),
        "metasploit_modules": int(item.get("metasploit_modules", 0) or 0),
        "source": "cve-explore",
    }


def _debug_response_shape(data, indent="    "):
    if isinstance(data, list):
        print(f"{indent}list[{len(data)}]")
        if data and isinstance(data[0], dict):
            print(f"{indent}  first keys: {list(data[0].keys())[:12]}")
    elif isinstance(data, dict):
        print(f"{indent}dict keys: {list(data.keys())[:15]}")
        for k, v in list(data.items())[:5]:
            if k == "facets":
                print(f"{indent}  {k}: {{...}} (facets)")
                continue
            if isinstance(v, list):
                print(f"{indent}  {k}: list[{len(v)}]")
                if v and isinstance(v[0], dict):
                    print(f"{indent}    first keys: {list(v[0].keys())[:12]}")
            elif isinstance(v, dict):
                sub_keys = list(v.keys())[:8]
                print(f"{indent}  {k}: dict {sub_keys}")
                if "hits" in v and isinstance(v["hits"], list):
                    print(f"{indent}    hits: [{len(v['hits'])}]")
                    if v["hits"]:
                        print(f"{indent}      first keys: "
                              f"{list(v['hits'][0].keys())[:12]}")
            elif isinstance(v, (str, int, float, bool)):
                print(f"{indent}  {k}: {repr(v)[:60]}")
    else:
        print(f"{indent}{type(data).__name__}: {repr(data)[:100]}")


# ═════════════════════════════════════════════════════════════════════
# CVEExplore client
# ═════════════════════════════════════════════════════════════════════

class CVEExplore:
    def __init__(self, token: Optional[str] = None,
                 timeout: int = 30, rate_limit_per_min: int = 300,
                 vpn: Optional[VPNGuardClient] = None,
                 notifier: Optional[TelegramNotifier] = None,
                 debug: bool = False):
        self.token = token or os.environ.get("CVE_EXPLORE_TOKEN")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.rate_limit = rate_limit_per_min
        self._last_request = 0.0
        self._min_interval = 60.0 / rate_limit_per_min
        self.cache = {}
        self.vpn = vpn
        self.notifier = notifier or TelegramNotifier()
        self.debug = debug

    def _headers(self):
        h = {"Accept": "application/json",
             "User-Agent": "cve-explore-py/6.0"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _respect_rate(self):
        elapsed = time.time() - self._last_request
        wait = self._min_interval - elapsed
        if wait > 0:
            await asyncio.sleep(wait)

    async def _raw_get(self, path, params=None):
        await self._respect_rate()
        url = f"{BASE_URL}{path}"
        full_url = f"{url}?{urlencode(params)}" if params else url
        if self.debug:
            print(f"[CVE-Explore] GET {full_url}")

        async with aiohttp.ClientSession(
            timeout=self.timeout, headers=self._headers()
        ) as s:
            async with s.get(url, params=params) as r:
                self._last_request = time.time()
                if r.status == 200:
                    raw = await r.text()
                    if self.debug:
                        print(f"[CVE-Explore] 200, bytes={len(raw)}")
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        print(f"[CVE-Explore] Invalid JSON: {raw[:300]}")
                        return None
                if r.status == 429:
                    print("[CVE-Explore] 429 → пауза 30s")
                    await asyncio.sleep(30)
                    raise RuntimeError("rate limited")
                if r.status == 401:
                    raise RuntimeError("unauthorized (проверь token)")
                if r.status == 403:
                    raise RuntimeError("forbidden")
                if r.status == 404:
                    return None
                body = await r.text()
                print(f"[CVE-Explore] HTTP {r.status}: {body[:200]}")
                raise RuntimeError(f"HTTP {r.status}")

    async def _get(self, path, params=None, use_cache=True):
        key = (path, tuple(sorted((params or {}).items())))
        if use_cache and key in self.cache:
            return self.cache[key]

        if self.vpn:
            result = await retry_with_vpn(
                self._raw_get, path, params,
                vpn=self.vpn, notifier=self.notifier,
                context=f"cve-explore {path}", max_retries=3,
            )
        else:
            try:
                result = await self._raw_get(path, params)
            except Exception as e:
                print(f"[CVE-Explore] error: {e}")
                return None

        if result is not None and use_cache:
            self.cache[key] = result
        return result

    async def health(self):
        return bool(await self._get(f"{API_PREFIX}/health"))

    async def stats(self):
        return await self._get(f"{API_PREFIX}/stats") or {}

    async def vendors(self):
        data = await self._get(f"{API_PREFIX}/vendors")
        return _extract_generic_list(data, ["vendors", "items", "data",
                                              "results"])

    async def vendor_products(self, vendor):
        data = await self._get(
            f"{API_PREFIX}/vendors/{vendor}/products"
        )
        return _extract_generic_list(data, ["products", "items", "data",
                                              "results"])

    async def recent(self, limit=20):
        data = await self._get(f"{API_PREFIX}/cves/recent",
                                {"limit": limit})
        return _extract_search_hits(data) or _extract_generic_list(data)

    async def trending(self):
        data = await self._get(f"{API_PREFIX}/cves/trending")
        return _extract_search_hits(data) or _extract_generic_list(data)

    async def get_cve(self, cve_id):
        return await self._get(f"{API_PREFIX}/cves/{cve_id}")

    async def get_pocs(self, cve_id):
        data = await self._get(f"{API_PREFIX}/cves/{cve_id}/pocs")
        return _extract_generic_list(data, ["pocs", "items", "data",
                                              "results"])

    async def search(self, query, has_poc=True, limit=100, page=1):
        params = {
            "q": query,
            "has_poc": "true" if has_poc else "false",
            "page": str(page),
            "limit": str(limit),
        }
        data = await self._get(f"{API_PREFIX}/cves/search", params)
        hits = _extract_search_hits(data)
        meta = _extract_search_meta(data)

        if self.debug:
            print(f"[CVE-Explore] search(q={query!r}, page={page}) "
                  f"→ {len(hits)} hits, total={meta.get('total', '?')}")

        if not hits and has_poc:
            params2 = {"q": query, "page": str(page), "limit": str(limit)}
            data2 = await self._get(f"{API_PREFIX}/cves/search", params2,
                                     use_cache=False)
            hits = _extract_search_hits(data2)
            meta = _extract_search_meta(data2)

        return hits, meta


# ═════════════════════════════════════════════════════════════════════
# collect_all_into_db — с дневным кэшем
# ═════════════════════════════════════════════════════════════════════

async def collect_all_into_db(conn, client: CVEExplore,
                               max_vendors: int = 0,
                               max_cves: int = 5000,
                               force: bool = False):
    notifier = client.notifier
    start = time.time()

    # ── Проверка кэша ────────────────────────────────────────────────
    if not force:
        history = fetch_history_check_today(conn)
        if history:
            stats = get_stats_from_db(conn)
            elapsed_str = history["last_fetch"][:19]
            print(f"[CVE-Explore] ✓ Данные за сегодня уже собраны "
                  f"({elapsed_str})")
            print(f"    Vendors: {stats['vendors']}, "
                  f"Products: {stats['products']}, "
                  f"CVEs: {stats['cves_total']}, "
                  f"PoC: {stats['cves_poc']}, "
                  f"KEV: {stats['cves_kev']}")

            await notifier.send(
                f"💾 <b>CVE-Explore: кэш за сегодня</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"📅 Дата: <code>{history['fetch_date']}</code>\n"
                f"⏰ Последний сбор: <code>{elapsed_str}</code>\n\n"
                f"📦 Вендоров: <b>{stats['vendors']}</b>\n"
                f"🧩 Продуктов: <b>{stats['products']}</b>\n"
                f"🔴 CVE всего: <b>{stats['cves_total']}</b>\n"
                f"⚠️ С PoC: <b>{stats['cves_poc']}</b>\n"
                f"🚨 KEV: <b>{stats['cves_kev']}</b>\n"
                f"🖥 Хостов: <b>{stats['hosts']}</b>\n\n"
                f"Использую данные из БД.\n"
                f"Для обновления: <code>--force</code>"
            )
            return stats

    # ── Первый сбор за сегодня ───────────────────────────────────────
    await notifier.send(
        "🕷 <b>CVE-Explore v6: старт сбора</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📋 Макс. вендоров: {max_vendors or 'все'}\n"
        f"📋 Макс. CVE: {max_cves}\n"
        f"📅 Дата: <code>{_today()}</code>"
    )

    # ── ЭТАП 1: Вендоры ────────────────────────────────────────────
    print("[CVE-Explore] Сбор вендоров...")
    vendors = await client.vendors()
    if max_vendors > 0:
        vendors = vendors[:max_vendors]

    vendor_list = []
    total_v = len(vendors)
    print(f"    Получено: {total_v}")

    if total_v == 0:
        await notifier.send(
            "⚠️ <b>Вендоры не получены</b>\n"
            "Проверь: <code>python3 cve_explore.py debug</code>"
        )
        fetch_history_record(conn, success=False,
                              note="vendors=0, API error")
        return get_stats_from_db(conn)

    for i, v in enumerate(vendors, 1):
        if isinstance(v, dict):
            name = v.get("vendor") or v.get("name") or v.get("value")
            count = v.get("count", v.get("cve_count", 0))
        elif isinstance(v, str):
            name, count = v, 0
        else:
            continue
        if not name or name == "n/a":
            continue
        db_upsert_vendor(conn, name, count)
        vendor_list.append(name)
        if i % 20 == 0 or i == total_v:
            await notifier.progress("Вендоры", i, total_v)

    await notifier.success(
        "Вендоры собраны",
        f"📦 <b>{len(vendor_list)}</b> вендоров"
    )

    # ── ЭТАП 2: Продукты ──────────────────────────────────────────
    print("[CVE-Explore] Сбор продуктов...")
    total_p = len(vendor_list)
    products_total = 0

    for i, vendor in enumerate(vendor_list, 1):
        try:
            products = await client.vendor_products(vendor)
            for p in products:
                if isinstance(p, dict):
                    pname = (p.get("product") or p.get("name")
                             or p.get("value"))
                    pcount = p.get("count", p.get("cve_count", 0))
                elif isinstance(p, str):
                    pname, pcount = p, 0
                else:
                    continue
                if pname:
                    db_upsert_product(conn, vendor, pname, pcount)
                    products_total += 1
        except Exception as e:
            print(f"    [!] {vendor}: {e}")
        if i % 10 == 0 or i == total_p:
            await notifier.progress(
                "Продукты", i, total_p,
                extra=f"Всего: {products_total}"
            )

    await notifier.success(
        "Продукты собраны",
        f"📦 <b>{products_total}</b> продуктов"
    )

    # ── ЭТАП 3: CVE ────────────────────────────────────────────────
    print("[CVE-Explore] Сбор CVE с PoC...")
    all_cves = {}

    print("  trending...")
    for c in await client.trending():
        cid = _extract_cve_id(c)
        if cid:
            all_cves[cid] = c
    print(f"  trending: {len(all_cves)}")

    print("  recent...")
    for c in await client.recent(limit=100):
        cid = _extract_cve_id(c)
        if cid:
            all_cves[cid] = c
    print(f"  after recent: {len(all_cves)}")

    await notifier.send(
        f"🔥 trending+recent: <b>{len(all_cves)}</b> CVE"
    )

    # Обход вендоров
    target_vendors = vendor_list[:100]
    total_q = len(target_vendors)
    print(f"  Обход {total_q} вендоров...")

    for q_idx, q in enumerate(target_vendors, 1):
        if max_cves > 0 and len(all_cves) >= max_cves:
            break
        try:
            hits, meta = await client.search(
                q, has_poc=True, limit=100, page=1
            )
            total_vendor = meta.get("total", 0)
            added = 0
            for c in hits:
                cid = _extract_cve_id(c)
                if cid and cid not in all_cves:
                    all_cves[cid] = c
                    added += 1
            print(f"    [{q_idx}/{total_q}] {q}: +{added}/{len(hits)} "
                  f"(в вендоре: {total_vendor}, всего {len(all_cves)})")
            if q_idx % 5 == 0 or q_idx == total_q:
                await notifier.progress(
                    "CVE поиск", q_idx, total_q,
                    extra=f"CVE: {len(all_cves)}"
                )
        except Exception as e:
            print(f"    [!] {q}: {e}")

    # Дополнительные популярные запросы
    popular_extra = [
        "log4j", "spring", "kubernetes", "docker", "jenkins",
        "confluence", "jira", "exchange", "vcenter", "citrix",
        "fortinet", "cisco", "palo alto", "vmware", "splunk",
    ]
    print(f"  + {len(popular_extra)} доп. запросов...")
    for q in popular_extra:
        if max_cves > 0 and len(all_cves) >= max_cves:
            break
        try:
            hits, meta = await client.search(
                q, has_poc=True, limit=100, page=1
            )
            added = 0
            for c in hits:
                cid = _extract_cve_id(c)
                if cid and cid not in all_cves:
                    all_cves[cid] = c
                    added += 1
            print(f"    '{q}': +{added} (всего {len(all_cves)})")
        except Exception as e:
            print(f"    [!] {q}: {e}")

    await notifier.send(
        f"📥 Собрано CVE: <b>{len(all_cves)}</b>\n"
        f"Записываю в БД..."
    )

    # Запись в БД
    total_cves = len(all_cves)
    written = 0
    has_poc_count = 0
    kev_count = 0

    for i, (cid, item) in enumerate(all_cves.items(), 1):
        normalized = _cve_item_to_db(item)
        if normalized:
            db_upsert_cve(conn, normalized)
            written += 1
            if normalized.get("has_poc"):
                has_poc_count += 1
            if normalized.get("kev_added_at"):
                kev_count += 1
        if i % 50 == 0 or i == total_cves:
            await notifier.progress("Запись CVE", i, total_cves)

    # Записать историю
    fetch_history_record(
        conn,
        vendors_count=len(vendor_list),
        products_count=products_total,
        cves_count=written,
        success=True,
        note=f"poc={has_poc_count}, kev={kev_count}",
    )

    elapsed = time.time() - start

    await notifier.success(
        "CVE-Explore завершён",
        f"📦 Вендоров: <b>{len(vendor_list)}</b>\n"
        f"🧩 Продуктов: <b>{products_total}</b>\n"
        f"🔴 CVE: <b>{written}</b>\n"
        f"⚠️ С PoC: <b>{has_poc_count}</b>\n"
        f"🚨 KEV: <b>{kev_count}</b>\n"
        f"⏱ {elapsed/60:.1f} мин\n\n"
        f"💾 Сохранено в БД. "
        f"Завтра будет свежий сбор."
    )

    print(f"[CVE-Explore] ✓ Готово: "
          f"{len(vendor_list)} вендоров, "
          f"{written} CVE ({has_poc_count} с PoC) "
          f"за {elapsed/60:.1f} мин")

    return get_stats_from_db(conn)


# ═════════════════════════════════════════════════════════════════════
# CLI команды
# ═════════════════════════════════════════════════════════════════════

def cmd_stats(db_path):
    conn = init_db(db_path)
    stats = get_stats_from_db(conn)

    history = fetch_history_check_today(conn)
    history_all = conn.execute(
        "SELECT fetch_date, last_fetch, vendors_count, products_count, "
        "cves_count, success FROM fetch_history "
        "ORDER BY fetch_date DESC LIMIT 10"
    ).fetchall()

    print("═" * 60)
    print("  LiveList DB Statistics")
    print("═" * 60)
    print(f"DB: {db_path}")
    print()
    print(f"📦 Вендоров:         {stats['vendors']}")
    print(f"🧩 Продуктов:        {stats['products']}")
    print(f"🔴 CVE всего:         {stats['cves_total']}")
    print(f"⚠️  CVE с PoC:         {stats['cves_poc']}")
    print(f"🚨 CVE в KEV:         {stats['cves_kev']}")
    print(f"🖥  Хостов:            {stats['hosts']}")
    print(f"🎯 Nuclei findings:  {stats['nuclei']}")

    print()
    print("─" * 60)
    print("  Cache status")
    print("─" * 60)
    if history:
        print(f"✅ Сегодня ({history['fetch_date']}) уже собран")
        print(f"   Последний: {history['last_fetch'][:19]}")
        print(f"   Vendors:   {history['vendors_count']}")
        print(f"   Products:  {history['products_count']}")
        print(f"   CVEs:      {history['cves_count']}")
    else:
        print(f"⚠️ Сегодня ({_today()}) ещё не собирал")
        print(f"   Запусти: python3 cve_explore.py collect")

    if history_all:
        print()
        print("─" * 60)
        print("  История (последние 10)")
        print("─" * 60)
        print(f"{'Date':<12} {'Vendors':>8} {'Products':>10} "
              f"{'CVEs':>8} {'OK':>4}")
        for row in history_all:
            fd, lf, v, p, c, ok = row
            print(f"{fd:<12} {v:>8} {p:>10} {c:>8} "
                  f"{'✓' if ok else '✗':>4}")

    print("═" * 60)
    conn.close()


def cmd_clear_cache(db_path):
    conn = init_db(db_path)
    conn.execute("DELETE FROM fetch_history")
    conn.commit()
    print("✓ История кэша очищена")
    conn.close()


# ═════════════════════════════════════════════════════════════════════
# DEBUG
# ═════════════════════════════════════════════════════════════════════

async def debug_mode():
    load_all_env()
    print("═" * 60)
    print("  CVE-Explore DEBUG v6")
    print("═" * 60)

    token = os.environ.get("CVE_EXPLORE_TOKEN")
    if not token:
        print("❌ CVE_EXPLORE_TOKEN не задан")
        return
    print(f"✓ Token: {token[:25]}...{token[-8:]}")

    vpn = VPNGuardClient()
    notifier = TelegramNotifier()
    print(f"VPN: {'✓' if await vpn.ping() else '✗'}")

    client = CVEExplore(token=token, vpn=vpn,
                        notifier=notifier, debug=True)

    print("\n" + "─" * 60 + "\n1. HEALTH\n" + "─" * 60)
    h = await client._raw_get(f"{API_PREFIX}/health")
    print(json.dumps(h, indent=2)[:400] if h else "None")

    print("\n" + "─" * 60 + "\n2. VENDORS\n" + "─" * 60)
    raw = await client._raw_get(f"{API_PREFIX}/vendors")
    if raw:
        _debug_response_shape(raw)
    vendors = await client.vendors()
    print(f"Extracted: {len(vendors)}")
    if vendors:
        print(f"First 3: {vendors[:3]}")

    print("\n" + "─" * 60 + "\n3. SEARCH apache\n" + "─" * 60)
    raw = await client._raw_get(
        f"{API_PREFIX}/cves/search",
        {"q": "apache", "has_poc": "true"}
    )
    if raw:
        print("Shape:")
        _debug_response_shape(raw)
        hits = _extract_search_hits(raw)
        print(f"\nExtracted hits: {len(hits)}")
        if hits:
            print(f"First CVE: {json.dumps(hits[0], indent=2)[:800]}")

    print("\n" + "─" * 60 + "\n4. TRENDING\n" + "─" * 60)
    raw = await client._raw_get(f"{API_PREFIX}/cves/trending")
    if raw:
        _debug_response_shape(raw)
    t = await client.trending()
    print(f"Extracted: {len(t)}")

    print("\n" + "═" * 60 + "\n  DEBUG завершён\n" + "═" * 60)


# ═════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════

async def _cli():
    import argparse

    load_all_env()

    p = argparse.ArgumentParser(description="CVE-Explore CLI v6")
    p.add_argument("action",
                   choices=["health", "search", "cve", "pocs",
                            "recent", "trending", "vendors",
                            "stats", "collect", "debug",
                            "clear-cache"])
    p.add_argument("value", nargs="?")
    p.add_argument("--token")
    p.add_argument("--db", default=LIVELIST_DB)
    p.add_argument("--max-vendors", type=int, default=0)
    p.add_argument("--max-cves", type=int, default=5000)
    p.add_argument("--no-vpn", action="store_true")
    p.add_argument("--no-telegram", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--force", action="store_true")
    args = p.parse_args()

    # Sync команды
    if args.action == "stats":
        cmd_stats(args.db)
        return
    if args.action == "clear-cache":
        cmd_clear_cache(args.db)
        return
    if args.action == "debug":
        await debug_mode()
        return

    # Async команды
    vpn = VPNGuardClient() if not args.no_vpn else None
    notifier = TelegramNotifier(enabled=not args.no_telegram)

    if args.action == "collect":
        conn = init_db(args.db)
        client = CVEExplore(
            token=args.token, vpn=vpn, notifier=notifier,
            debug=args.debug,
        )
        await collect_all_into_db(
            conn, client,
            max_vendors=args.max_vendors,
            max_cves=args.max_cves,
            force=args.force,
        )
        conn.close()
        return

    client = CVEExplore(
        token=args.token, vpn=vpn, notifier=notifier,
        debug=args.debug,
    )

    if args.action == "health":
        print(f"Health: {'✓' if await client.health() else '✗'}")
    elif args.action == "search":
        hits, meta = await client.search(args.value or "",
                                          has_poc=True, limit=100)
        print(f"Найдено: {len(hits)} / total={meta.get('total', '?')}")
        for h in hits[:20]:
            cid = _extract_cve_id(h)
            score = h.get("cvss_v3_score", "?")
            poc = h.get("poc_count", 0)
            print(f"  {cid}  cvss={score}  pocs={poc}")
    elif args.action == "cve":
        print(json.dumps(await client.get_cve(args.value),
                         indent=2, ensure_ascii=False))
    elif args.action == "pocs":
        pocs = await client.get_pocs(args.value)
        print(f"PoCs: {len(pocs)}")
        print(json.dumps(pocs, indent=2, ensure_ascii=False))
    elif args.action == "recent":
        print(json.dumps(await client.recent(20),
                         indent=2, ensure_ascii=False))
    elif args.action == "trending":
        print(json.dumps(await client.trending(),
                         indent=2, ensure_ascii=False))
    elif args.action == "vendors":
        vs = await client.vendors()
        print(f"Vendors: {len(vs)}")
        for v in vs[:30]:
            print(f"  {v}")
    elif args.action == "stats":
        print(json.dumps(await client.stats(),
                         indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(_cli())
