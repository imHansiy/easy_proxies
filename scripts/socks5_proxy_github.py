#!/usr/bin/env python3
import json
import os
import re
import sys
import urllib.request
from urllib.parse import urlsplit


HOME_URL = "https://socks5-proxy.github.io/"
ALL_URL = "https://socks5-proxy.github.io/allproxy.html"

PATTERNS = [
    r"copyProxy\(\s*this\s*,\s*'([^']+)'\s*\)",
    r'copyProxy\(\s*this\s*,\s*"([^"]+)"\s*\)',
]


def fetch(url: str, timeout: float = 12.0) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "easy-proxies-script/1.0",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return data.decode("utf-8", "replace")


def parse_nodes(html: str):
    items = []
    for pat in PATTERNS:
        items.extend(re.findall(pat, html))

    seen = set()
    nodes = []

    for raw in items:
        raw = (raw or "").strip()
        if not raw:
            continue

        # raw looks like: "socks5://1.2.3.4:1080 [2026-03-04 18:39]"
        uri = raw.split(" ", 1)[0].strip()
        if not uri or uri in seen:
            continue
        seen.add(uri)

        u = urlsplit(uri)
        scheme = (u.scheme or "").lower()
        host = u.hostname
        port = u.port

        if not host or not port:
            continue
        if scheme not in ("socks", "socks5", "socks5h", "socks4", "socks4a", "http", "https"):
            continue

        updated = ""
        m = re.search(r"\[([^\]]+)\]", raw)
        if m:
            updated = m.group(1).strip()

        name = f"{scheme.upper()} {host}:{port}"
        if updated:
            name += f" {updated}"

        nodes.append({"name": name, "uri": uri})

    return nodes


def main():
    url = HOME_URL
    limit = 60

    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--all":
            url = ALL_URL
        elif a == "--url" and i + 1 < len(argv):
            url = argv[i + 1]
            i += 1
        elif a == "--limit" and i + 1 < len(argv):
            try:
                limit = int(argv[i + 1])
            except Exception:
                pass
            i += 1
        i += 1

    # Optional: the platform may pass a JSON object to stdin.
    _ = sys.stdin.read()

    html = fetch(url)
    nodes = parse_nodes(html)
    if limit and limit > 0:
        nodes = nodes[:limit]

    print(
        f"source={os.getenv('EP_SOURCE_NAME')} url={url} parsed={len(nodes)}",
        file=sys.stderr,
    )
    sys.stdout.write(json.dumps({"nodes": nodes}, ensure_ascii=True))


if __name__ == "__main__":
    main()
