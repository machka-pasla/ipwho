"""Subscription fetcher/parsers for proxy lists."""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

import aiohttp

from .proxies import extract_proxy_uris, parse_proxy_link

SUBSCRIPTION_HEADERS = {
    'User-Agent': 'ip-who-bot/1.0',
    'X-HWID': 'b16ae9eb-8434-4278-ad61-74567517091f',
}


async def fetch_subscription_entries(url: str) -> list[dict[str, Any]] | None:
    raw = await _fetch_raw_subscription(url)
    if raw is None:
        return None

    entries: list[dict[str, Any]] = []
    entries.extend(_parse_base64_blob(raw))
    entries.extend(_parse_json_blob(raw))
    return entries or None


async def _fetch_raw_subscription(url: str) -> bytes | None:
    try:
        async with aiohttp.ClientSession(headers=SUBSCRIPTION_HEADERS) as session:
            async with session.get(url, timeout=15) as response:
                if response.status != 200:
                    return None
                return await response.read()
    except Exception as exc:
        logging.warning("Sub fetch error %s: %s", url, exc)
        return None


def _parse_base64_blob(raw: bytes) -> list[dict[str, Any]]:
    try:
        decoded = base64.b64decode(raw).decode('utf-8', errors='ignore')
    except Exception:
        return []

    infos: list[dict[str, Any]] = []
    for link in _extract_links(decoded):
        if info := parse_proxy_link(link):
            infos.append(info)
    return infos


def _extract_links(text: str | None) -> list[str]:
    if not text:
        return []
    return extract_proxy_uris(text)


def _parse_json_blob(raw: bytes) -> list[dict[str, Any]]:
    try:
        data = json.loads(raw.decode('utf-8', errors='ignore'))
    except Exception:
        return []

    if not isinstance(data, list):
        return []

    infos: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, str):
            if info := parse_proxy_link(item):
                infos.append(info)
            continue
        if isinstance(item, dict):
            infos.extend(_parse_clash_like_entry(item))
    return infos


def _parse_clash_like_entry(entry: dict[str, Any]) -> list[dict[str, Any]]:
    outbounds = entry.get("outbounds")
    if not isinstance(outbounds, list):
        return []

    results: list[dict[str, Any]] = []
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        proto_raw = (outbound.get("protocol") or "").lower()
        proto = 'ss' if proto_raw == 'shadowsocks' else proto_raw
        settings = outbound.get("settings") or {}
        stream = outbound.get("streamSettings") or {}

        addr, port_val = _extract_address(proto, settings)
        if not addr:
            continue

        info = {
            'protocol': proto or None,
            'server': addr,
            'port': port_val,
            'sni': _extract_sni(proto, outbound, settings, stream, addr) or None,
            'type': stream.get("network") or outbound.get("network") or outbound.get("type"),
            'security': stream.get("security"),
            'method': _extract_method(proto, settings),
            'comment': (
                outbound.get("tag")
                or outbound.get("name")
                or entry.get("remarks")
                or entry.get("name")
            ),
        }
        clean = {k: v for k, v in info.items() if v not in (None, '')}
        if clean:
            results.append(clean)
    return results


def _extract_address(proto: str, settings: dict[str, Any]) -> tuple[str | None, str | int | None]:
    vnext = settings.get("vnext")
    if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
        entry = vnext[0]
        return entry.get("address"), entry.get("port")

    if proto in {"ss", "trojan"}:
        servers = settings.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            srv = servers[0]
            return srv.get("address"), srv.get("port")
    return None, None


def _extract_sni(proto: str, outbound: dict[str, Any], settings: dict[str, Any],
                 stream: dict[str, Any], addr: str | None) -> str | None:
    sni = (
        outbound.get("serverName")
        or outbound.get("server_name")
        or outbound.get("sni")
        or settings.get("serverName")
        or settings.get("server_name")
        or settings.get("sni")
    )
    if not sni:
        reality = stream.get("realitySettings") or {}
        sni = (
            reality.get("serverName")
            or reality.get("server_name")
            or reality.get("sni")
        )
    if proto == 'vless' and not sni and isinstance(outbound.get("settings"), dict):
        sni = outbound.get("settings", {}).get("address")
    if proto == 'vless' and not sni:
        sni = addr
    return sni


def _extract_method(proto: str, settings: dict[str, Any]) -> str | None:
    if proto != 'ss':
        return None
    method = settings.get("method")
    if method:
        return method
    servers = settings.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        return servers[0].get("method")
    return None


__all__ = ['fetch_subscription_entries']
