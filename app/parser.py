"""Text parsing utilities for extracting hosts and proxy extras."""
from __future__ import annotations

import re
from typing import Any

from .host_utils import DOMAIN_PATTERN, is_ipv6, normalize_host_key, resolve_hostname
from .proxies import extract_host_from_link, extract_proxy_uris, parse_proxy_link
from .proxy_utils import PROXY_SCHEMES as PROXY_SCHEME_LIST

PROXY_SCHEMES_REGEX = r'(?:' + '|'.join(PROXY_SCHEME_LIST) + ')'


async def parse_message_text(text: str) -> tuple[list[tuple[str, list[str]]],
                                                 dict[str, list[dict[str, Any]]]]:
    extras_map: dict[str, list[dict[str, Any]]] = {}
    for link in extract_proxy_uris(text):
        if info := parse_proxy_link(link):
            server = info.get('server')
            if server:
                extras_map.setdefault(normalize_host_key(server), []).append(info)

    domain_rx = DOMAIN_PATTERN
    items = re.findall(
        rf'{PROXY_SCHEMES_REGEX}://[^\s]+|https?://[^\s]+|{domain_rx}|'
        rf'(?:\d{{1,3}}\.){{3}}\d{{1,3}}|'
        rf'(?:[A-Fa-f0-9]{{1,4}}:)+[A-Fa-f0-9]{{1,4}}',
        text)

    # Дополнительный поиск IPv6 (включая сокращённые формы с ::)
    for token in re.findall(r'[0-9A-Fa-f:\.]{2,}', text):
        if ':' in token and is_ipv6(token) and token not in items:
            items.append(token)

    resolved: list[tuple[str, list[str]]] = []
    seen_hosts: set[str] = set()
    for entry in items:
        host = extract_host_from_link(entry)
        if not host:
            if re.fullmatch(rf'({domain_rx})|(\d{{1,3}}(\.\d{{1,3}}){{3}})', entry) \
               or is_ipv6(entry):
                host = entry
        if not host:
            continue
        norm = normalize_host_key(host)
        if norm in seen_hosts:
            continue
        if ips := await resolve_hostname(host):
            resolved.append((host, ips))
            seen_hosts.add(norm)
    return resolved, extras_map


__all__ = ['parse_message_text']
