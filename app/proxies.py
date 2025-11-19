"""Helpers for working with proxy links and resolving hosts from URIs."""
from __future__ import annotations

import re

from .proxy_utils import extract_proxy_uris, parse_proxy_uri

__all__ = ['extract_proxy_uris', 'parse_proxy_link', 'extract_host_from_link']


def parse_proxy_link(link: str) -> dict | None:
    """Return parsed proxy info dict (protocol, server, port, sni, etc.)."""
    info = parse_proxy_uri(link)
    server = info.get('server') if isinstance(info, dict) else None
    if not server:
        return None
    if info.get('protocol') == 'vless' and not info.get('sni'):
        info['sni'] = server
    return info


def extract_host_from_link(link: str) -> str | None:
    info = parse_proxy_link(link)
    if info:
        return info.get('server')
    # IPv6 in URLs can be wrapped in []
    match = re.search(r'https?://\[(?P<ip>[^\]]+)\]', link)
    if match:
        return match.group('ip')
    match = re.search(r'https?://(?:www\.)?([^:/?#&]+)', link)
    return match.group(1) if match else None
