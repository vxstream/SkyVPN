#!/usr/bin/env python3
"""
VPN Subscription Checker
Reads sources.txt (vless:// or http(s):// links),
fetches configs, checks TCP connectivity, outputs sub.txt
with plain subscription headers (profile-title, announce, etc.)
"""

import base64
import socket
import urllib.request
from urllib.parse import unquote
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

SOURCES_FILE = "sources.txt"
OUTPUT_FILE  = "sub.txt"

# ── Ремарки ──────────────────────────────────
# True  → оставляем оригинальные #fragment из конфигов
# False → ставим свои: REMARK_PREFIX + порядковый номер
USE_ORIGINAL_REMARKS = True
REMARK_PREFIX        = "SkyVPN - "   # используется только если USE_ORIGINAL_REMARKS = False

# ── Plain-subscription заголовки ─────────────
# Отображаются в клиентах (Happ, v2rayNG, Streisand, Nekoray и т.д.)
PROFILE_TITLE   = "SkyVPN"
PROFILE_UPDATE  = 1800        # интервал обновления в секундах (30 мин = 1800)

# Текст анонса — отображается внутри клиента под названием профиля.
# {count}    → кол-во живых конфигов
# {updated}  → время обновления UTC
# {date}     → дата обновления UTC
ANNOUNCE_TEMPLATE = (
    "🚀 SkyVPN — бесплатный VPN\n"
    "⏰ Обновлено: {updated} UTC\n"
    #"✅ Живых серверов: {count}\n"
    #"💬 Трафик: безлимитный"
)

# ── TCP-проверка ──────────────────────────────
TCP_TIMEOUT = 10
MAX_WORKERS = 500


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def fetch_url(url: str) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
        # Пробуем base64-decode (большинство подписок так упакованы)
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


def parse_host_port(uri: str) -> tuple[str, int] | None:
    try:
        without_scheme = uri.split("://", 1)[1]
        at_idx = without_scheme.rfind("@")
        if at_idx == -1:
            return None
        host_part = re.split(r"[?#]", without_scheme[at_idx + 1:])[0]
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
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except Exception:
        return False


def set_remark(uri: str, remark: str) -> str:
    uri = re.sub(r"#.*$", "", uri.rstrip())
    return f"{uri}#{remark}"


def get_remark(uri: str) -> str | None:
    m = re.search(r"#(.+)$", uri)
    return unquote(m.group(1)) if m else None


def collect_uris(text: str) -> list[str]:
    return re.findall(r"(?:vless|vmess|ss|trojan|hy2|hysteria2)://[^\s]+", text)


# ─────────────────────────────────────────────
#  PLAIN SUBSCRIPTION HEADER BUILDER
# ─────────────────────────────────────────────

def build_plain_header(count: int, updated: str) -> str:
    """
    Формат plain-subscription заголовков.
    Клиенты читают строки вида:  # key: value
    Поддерживается: Happ, v2rayNG ≥1.8, Streisand, Nekoray, Karing и др.

    announce кодируется в base64 одной строкой, чтобы поддержать многострочный текст.
    """
    announce_text = ANNOUNCE_TEMPLATE.format(
        count=count,
        updated=updated,
        date=updated.split()[0],
    )
    announce_b64 = base64.b64encode(announce_text.encode("utf-8")).decode("ascii")

    return (
        f"# profile-title: {PROFILE_TITLE}\n"
        f"# profile-update-interval: {PROFILE_UPDATE}\n"
        f"# subscription-userinfo: upload=0; download=0; total=0; expire=0\n"
        f"# announce: base64:{announce_b64}\n"
        f"# generated: {updated} UTC\n"
        f"# total-count: {count}\n"
    )


# ─────────────────────────────────────────────
#  PIPELINE
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
        if "://" in src and not src.startswith("http"):
            all_uris.append(src)
        elif src.startswith("http://") or src.startswith("https://"):
            print(f"  → Подписка: {src}")
            text = fetch_url(src)
            if text:
                found = collect_uris(text)
                print(f"    Найдено конфигов: {len(found)}")
                all_uris.extend(found)
        else:
            print(f"  [?] Неизвестный источник: {src}", file=sys.stderr)
    return all_uris


def deduplicate(uris: list[str]) -> list[str]:
    seen, result = set(), []
    for uri in uris:
        key = re.sub(r"#.*$", "", uri.strip())
        if key not in seen:
            seen.add(key)
            result.append(uri)
    return result


def check_all(uris: list[str]) -> list[str]:
    valid: list[str] = []
    tasks: dict = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for uri in uris:
            hp = parse_host_port(uri)
            if hp is None:
                continue
            tasks[pool.submit(tcp_check, hp[0], hp[1])] = uri

        done, total = 0, len(tasks)
        for future in as_completed(tasks):
            done += 1
            uri = tasks[future]
            ok  = future.result()
            hp  = parse_host_port(uri)
            print(f"  [{'✓' if ok else '✗'}] [{done}/{total}] {hp[0]}:{hp[1]}")
            if ok:
                valid.append(uri)

    return valid


def apply_remarks(uris: list[str]) -> list[str]:
    result = []
    for i, uri in enumerate(uris, start=1):
        if USE_ORIGINAL_REMARKS:
            remark = get_remark(uri) or f"{REMARK_PREFIX}{i}"
            result.append(set_remark(uri, remark))
        else:
            result.append(set_remark(uri, f"{REMARK_PREFIX}{i}"))
    return result


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print("=" * 52)
    print("  SkyVPN — Subscription Builder")
    print("=" * 52)

    sources = load_sources(SOURCES_FILE)
    if not sources:
        print("[!] sources.txt пуст. Добавь ссылки на подписки.")
        return

    print(f"\n[1/3] Источников: {len(sources)}. Собираем конфиги...")
    all_uris = deduplicate(gather_all_uris(sources))
    print(f"      Уникальных конфигов: {len(all_uris)}")

    print(f"\n[2/3] TCP-проверка...")
    valid = check_all(all_uris)
    print(f"\n      Живых: {len(valid)} / {len(all_uris)}")

    print(f"\n[3/3] Формируем {OUTPUT_FILE}...")
    final   = apply_remarks(valid)
    updated = time.strftime("%Y-%m-%d %H:%M", time.gmtime())
    header  = build_plain_header(len(final), updated)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for uri in final:
            f.write(uri + "\n")

    print(f"\n✓ Готово! {len(final)} серверов → {OUTPUT_FILE}")
    print("=" * 52)


if __name__ == "__main__":
    main()
