#!/usr/bin/env python3
"""
VPN Subscription Checker
Reads sources.txt (vless:// or http(s):// links),
fetches configs, checks TCP connectivity, outputs sub.txt
"""

import asyncio
import base64
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse, unquote
import re
import sys
import time

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

SOURCES_FILE = "sources.txt"
OUTPUT_FILE  = "sub.txt"

# Если True — сохраняем оригинальные ремарки (#fragment) из конфигов
# Если False — ставим свои ремарки: REMARK_PREFIX + порядковый номер
USE_ORIGINAL_REMARKS = True
REMARK_PREFIX        = "FreeVPN-"   # используется только если USE_ORIGINAL_REMARKS = False

# TCP-проверка: таймаут в секундах
TCP_TIMEOUT  = 5
# Максимум параллельных TCP-проверок
MAX_WORKERS  = 100

# Заголовок / баннер, добавляется первой строкой в sub.txt
# Оставь пустой строкой "", чтобы не добавлять
BANNER = f"# Updated: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} | Free VLESS configs"


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def fetch_url(url: str) -> str | None:
    """Скачивает текст по URL, возвращает None при ошибке."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
        # Пробуем base64-decode (формат большинства подписок)
        try:
            decoded = base64.b64decode(raw + b"==").decode("utf-8", errors="ignore")
            if decoded.startswith(("vless://", "vmess://", "ss://", "trojan://", "hy2://", "hysteria2://")):
                return decoded
        except Exception:
            pass
        return raw.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  [!] Не удалось загрузить {url}: {e}", file=sys.stderr)
        return None


def parse_vless_host_port(uri: str) -> tuple[str, int] | None:
    """Извлекает (host, port) из vless:// URI."""
    try:
        # vless://uuid@host:port?...#remark
        without_scheme = uri[len("vless://"):]
        at_idx = without_scheme.rfind("@")
        if at_idx == -1:
            return None
        host_part = without_scheme[at_idx + 1:]
        # убираем query и fragment
        host_part = re.split(r"[?#]", host_part)[0]
        # host:port  или  [ipv6]:port
        if host_part.startswith("["):
            m = re.match(r"\[([^\]]+)\]:(\d+)", host_part)
        else:
            m = re.match(r"([^:]+):(\d+)", host_part)
        if not m:
            return None
        return m.group(1), int(m.group(2))
    except Exception:
        return None


def tcp_check(host: str, port: int) -> bool:
    """Синхронная TCP-проверка доступности."""
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def set_remark(uri: str, remark: str) -> str:
    """Заменяет или добавляет #remark в URI."""
    uri = re.sub(r"#.*$", "", uri.rstrip())
    return f"{uri}#{remark}"


def get_remark(uri: str) -> str | None:
    """Возвращает текущую ремарку из URI или None."""
    m = re.search(r"#(.+)$", uri)
    if m:
        return unquote(m.group(1))
    return None


def collect_vless_uris(text: str) -> list[str]:
    """Извлекает все vless:// URI из текста."""
    return re.findall(r"vless://[^\s]+", text)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def load_sources(path: str) -> list[str]:
    sources = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    sources.append(line)
    except FileNotFoundError:
        print(f"[!] Файл {path} не найден", file=sys.stderr)
    return sources


def gather_all_uris(sources: list[str]) -> list[str]:
    all_uris: list[str] = []
    for src in sources:
        if src.startswith("vless://"):
            all_uris.append(src)
        elif src.startswith("http://") or src.startswith("https://"):
            print(f"  → Загружаем подписку: {src}")
            text = fetch_url(src)
            if text:
                found = collect_vless_uris(text)
                print(f"    Найдено vless-конфигов: {len(found)}")
                all_uris.extend(found)
        else:
            print(f"  [?] Неизвестный формат источника: {src}", file=sys.stderr)
    return all_uris


def check_all(uris: list[str]) -> list[str]:
    """Параллельная TCP-проверка через ThreadPoolExecutor."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    valid: list[str] = []
    tasks: dict = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for uri in uris:
            hp = parse_vless_host_port(uri)
            if hp is None:
                continue
            future = pool.submit(tcp_check, hp[0], hp[1])
            tasks[future] = uri

        done = 0
        total = len(tasks)
        for future in as_completed(tasks):
            done += 1
            uri = tasks[future]
            ok = future.result()
            hp = parse_vless_host_port(uri)
            status = "✓" if ok else "✗"
            print(f"  [{done}/{total}] {status} {hp[0]}:{hp[1]}")
            if ok:
                valid.append(uri)

    return valid


def apply_remarks(uris: list[str]) -> list[str]:
    result = []
    for i, uri in enumerate(uris, start=1):
        if USE_ORIGINAL_REMARKS:
            remark = get_remark(uri)
            if not remark:
                remark = f"{REMARK_PREFIX}{i}"
            result.append(set_remark(uri, remark))
        else:
            result.append(set_remark(uri, f"{REMARK_PREFIX}{i}"))
    return result


def main():
    print("=" * 50)
    print("  VPN Subscription Checker")
    print("=" * 50)

    sources = load_sources(SOURCES_FILE)
    if not sources:
        print("[!] Нет источников для проверки. Добавь ссылки в sources.txt")
        return

    print(f"\n[1/3] Источников: {len(sources)}. Собираем конфиги...")
    all_uris = gather_all_uris(sources)

    # Дедупликация по базовому URI (без ремарки)
    seen = set()
    deduped = []
    for uri in all_uris:
        key = re.sub(r"#.*$", "", uri.strip())
        if key not in seen:
            seen.add(key)
            deduped.append(uri)

    print(f"\n[2/3] Всего уникальных конфигов: {len(deduped)}. Проверяем TCP...")
    valid = check_all(deduped)
    print(f"\n  Живых конфигов: {len(valid)} / {len(deduped)}")

    print(f"\n[3/3] Применяем ремарки и сохраняем в {OUTPUT_FILE}...")
    final = apply_remarks(valid)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        if BANNER:
            f.write(BANNER + "\n")
        for uri in final:
            f.write(uri + "\n")

    print(f"\n✓ Готово! Сохранено {len(final)} конфигов → {OUTPUT_FILE}")
    print("=" * 50)


if __name__ == "__main__":
    main()
