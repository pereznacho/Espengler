#!/usr/bin/env python3
"""
Descarga los logos OFICIALES en formato SVG para el GraphMap.
SOLO SVG. NUNCA se usan PNG para iconos de sistemas operativos.

- Windows (todas las versiones): Wikimedia Commons (logos oficiales Microsoft).
- Resto (Linux, Ubuntu, Debian, Kali, Arch, Fedora, Red Hat, macOS, Android): Simple Icons
  (https://simpleicons.org), logos oficiales de cada marca, CC0-1.0.

Ejecutar desde la raíz: python3 scripts/download_graphmap_logos.py
"""
import os
import sys
import urllib.request
import ssl

# Simple Icons: (local name, slug, hex color). Windows generic not on CDN; repo has fallback.
LOGOS_SIMPLEICONS = [
    ("windows", "microsoftwindows", "0078D6"),  # 404 on CDN; overwritten by Windows downloads below
    ("linux", "linux", "FCC624"),
    ("ubuntu", "ubuntu", "E95420"),
    ("debian", "debian", "A81D33"),
    ("kali", "kalilinux", "557C94"),
    ("arch", "archlinux", "1793D1"),
    ("fedora", "fedora", "294094"),
    ("redhat", "redhat", "EE0000"),
    ("macos", "apple", "000000"),
    ("android", "android", "3DDC84"),
]

# Windows version logos from Wikimedia Commons (Microsoft logos; see Commons file pages).
# 2012 = symbol used for Windows 8 / Windows Server 2012 / Windows 10. 2021 = Windows 11.
# XP/Vista/7: no symbol-only official SVG on Commons; we use 2012 symbol (official Microsoft).
WINDOWS_LOGOS = [
    ("windows", "https://upload.wikimedia.org/wikipedia/commons/8/87/Windows_logo_-_2021.svg"),
    ("windows_xp", "https://upload.wikimedia.org/wikipedia/commons/0/0a/Unofficial_Windows_logo_variant_-_2002%E2%80%932012_%28Multicolored%29.svg"),
    ("windows_vista", "https://upload.wikimedia.org/wikipedia/commons/5/5f/Windows_logo_-_2012.svg"),
    ("windows_7", "https://upload.wikimedia.org/wikipedia/commons/5/5f/Windows_logo_-_2012.svg"),
    ("windows_8", "https://upload.wikimedia.org/wikipedia/commons/5/5f/Windows_logo_-_2012.svg"),
    ("windows_10", "https://upload.wikimedia.org/wikipedia/commons/5/5f/Windows_logo_-_2012.svg"),
    ("windows_11", "https://upload.wikimedia.org/wikipedia/commons/8/87/Windows_logo_-_2021.svg"),
    ("windows_12", "https://upload.wikimedia.org/wikipedia/commons/8/87/Windows_logo_-_2021.svg"),
    ("windows_server", "https://upload.wikimedia.org/wikipedia/commons/5/5f/Windows_logo_-_2012.svg"),
]

UNKNOWN_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#6E7681" stroke-width="2" stroke-linecap="round">
  <circle cx="12" cy="12" r="10"/>
  <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>
  <line x1="12" y1="17" x2="12.01" y2="17"/>
</svg>
"""


def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    graphmap = os.path.join(base, "static", "images", "graphmap")
    os.makedirs(graphmap, exist_ok=True)
    ctx = ssl.create_default_context()
    headers = {"User-Agent": "Espengler/1.0 (https://github.com/pereznacho/Espengler)"}

    # 1) Windows version logos (Wikimedia Commons – official Microsoft logos)
    print("Downloading Windows logos (Wikimedia Commons)...")
    for local_name, url in WINDOWS_LOGOS:
        path = os.path.join(graphmap, f"{local_name}.svg")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                data = r.read()
            with open(path, "wb") as f:
                f.write(data)
            print("  OK:", f"{local_name}.svg")
        except Exception as e:
            print("  Skip", local_name, ":", e)

    # 2) Rest: Simple Icons (skip "windows", already from Commons)
    print("Downloading other OS logos (Simple Icons)...")
    for local_name, slug, color in LOGOS_SIMPLEICONS:
        if local_name == "windows":
            continue
        url = f"https://cdn.simpleicons.org/{slug}/{color}"
        path = os.path.join(graphmap, f"{local_name}.svg")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                data = r.read()
            with open(path, "wb") as f:
                f.write(data)
            print("  OK:", f"{local_name}.svg")
        except Exception as e:
            print("  Skip", local_name, ":", e)

    unknown_path = os.path.join(graphmap, "unknown.svg")
    if not os.path.isfile(unknown_path):
        with open(unknown_path, "w", encoding="utf-8") as f:
            f.write(UNKNOWN_SVG)
        print("OK: unknown.svg (placeholder)")

    print("Done. Todos los iconos del mapa usan solo estos SVG (nunca PNG).")


if __name__ == "__main__":
    main()
