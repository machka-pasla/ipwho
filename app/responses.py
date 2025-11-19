"""Formatting helpers for replies sent to Telegram."""
from __future__ import annotations

import html
import logging
import re
from typing import Any

import aiohttp
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from .host_utils import (
    build_whois_url,
    classify_local_ip,
    fetch_ech_status,
    is_domain_name,
    is_local_ip,
)
from .ip_state import register_ip_state


async def fetch_ip_info(ip: str) -> dict:
    url = f"http://ipwho-web:30000/json/{ip}"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as exc:
            logging.error("IP info fetch error %s: %s", ip, exc)
            return {}


def format_org(org: str) -> str:
    parts = org.split(" ", 1)
    return f"{parts[0]} / {parts[1]}" if len(parts) == 2 else org


def html_escape(val: str | None) -> str:
    return html.escape(val or "", quote=True)


def strip_html(text: str) -> str:
    # naive removal, acceptable for short snippets
    no_tags = re.sub(r'<[^>]+>', '', text)
    return html.unescape(no_tags).strip()


async def build_info_text(host: str, ip: str, extras: dict | None) -> str:
    data = await fetch_ip_info(ip)
    host_safe = html_escape(host)
    lines: list[str] = []

    def add_blank_line() -> None:
        if lines and lines[-1] != "":
            lines.append("")

    if extras:
        comment = extras.get('comment')
        if comment:
            suffix = "…" if extras.get('comment_truncated') else ""
            lines.append(html_escape(f"{comment}{suffix}"))
    config_lines: list[str] = []
    if extras:
        for key in ("protocol", "server", "port", "type", "security", "sni", "host", "method"):
            val = extras.get(key)
            if val is None:
                continue
            if isinstance(val, str) and not val.strip():
                continue
            safe_val = html_escape(str(val))
            config_lines.append(f"<code>{key}={safe_val}</code>")
    if config_lines:
        add_blank_line()
        lines.extend(config_lines)

    if host and host != ip:
        add_blank_line()
        suffix = ""
        if is_domain_name(host):
            ech_status = await fetch_ech_status(host)
            if ech_status is True:
                suffix = " (ECH ON)"
        lines.append(f"<code>{host_safe}</code>{suffix}")

    add_blank_line()
    lines.append(f"<code>{html_escape(ip)}</code>")

    if not data:
        lines.append("")
        lines.append("Failed to get geo info")
        return "\n".join(lines)

    mm = data.get("maxmind", {})
    ii = data.get("ipinfo", {})
    local = is_local_ip(ip)

    if local:
        local_label = classify_local_ip(ip) or "Private Network IP"
        lines.append("")
        lines.append(html_escape(local_label))
        return "\n".join(lines)

    def join_non_empty(parts: list[str]) -> str:
        return " / ".join([p for p in parts if p])

    mm_lines: list[str] = []
    mm_has_geo = False
    mm1 = join_non_empty([
        mm.get('country_code', ''),
        mm.get('country_name', ''),
        mm.get('city_name', ''),
    ])
    if mm1:
        mm_lines.append(html_escape(mm1))
        mm_has_geo = True
    mm2 = join_non_empty([
        mm.get('asn', ''),
        mm.get('as_desc', ''),
    ])
    if mm2:
        mm_lines.append(html_escape(mm2))

    ii_lines: list[str] = []
    ii_has_geo = False
    cc = ii.get('country', '')
    cname = ii.get('country_name', '') if cc else ''
    ii1 = join_non_empty([
        cc,
        cname,
        ii.get('city', ''),
    ])
    if ii1:
        ii_lines.append(html_escape(ii1))
        ii_has_geo = True
    org_val = ii.get('org', '')
    if org_val:
        ii_lines.append(html_escape(format_org(org_val)))

    def append_geo_section(title: str, entries: list[str],
                           has_geo_data: bool = True) -> None:
        add_blank_line()
        lines.append(title)
        if not entries:
            lines.append("No geo info")
            return
        if not has_geo_data:
            lines.append("No geo info")
        lines.extend(entries)

    append_geo_section("MaxMind", mm_lines, has_geo_data=mm_has_geo)
    append_geo_section("IPinfo", ii_lines, has_geo_data=ii_has_geo)

    return "\n".join(lines)


async def build_host_response(host: str, ips: list[str],
                              extras: dict | None) -> tuple[str, InlineKeyboardMarkup | None]:
    if not ips:
        return f"Failed to resolve {host}", None

    nav_info: dict[str, Any] | None = None
    total = len(ips)
    if total > 1:
        state_id = register_ip_state(host, ips, extras)
        nav_info = {'state_id': state_id, 'index': 0, 'total': total}

    text = await build_info_text(host, ips[0], extras)
    keyboard = create_keyboard(host, ips[0], nav_info)
    return text, keyboard


def create_keyboard(host: str, ip: str,
                    nav_info: dict[str, Any] | None = None) -> InlineKeyboardMarkup | None:
    rows: list[list[InlineKeyboardButton]] = []

    if not is_local_ip(ip):
        rows.extend([
            [InlineKeyboardButton(text="BGP", url=f"https://bgp.tools/prefix-selector?ip={ip}")],
            [InlineKeyboardButton(text="Censys", url=f"https://search.censys.io/hosts/{ip}")],
            [InlineKeyboardButton(text="IPinfo", url=f"https://ipinfo.io/{ip}")],
        ])
    whois_url = build_whois_url(host)
    if whois_url:
        rows.append([InlineKeyboardButton(text="WHOIS", url=whois_url)])

    if nav_info and nav_info.get('total', 1) > 1:
        state_id = nav_info.get('state_id', '')
        index = max(int(nav_info.get('index', 0)), 0)
        total = max(int(nav_info.get('total', 1)), 1)
        nav_row: list[InlineKeyboardButton] = []

        if index > 0:
            nav_row.append(InlineKeyboardButton(
                text="←",
                callback_data=f"nav|{state_id}|{index - 1}"
            ))

        nav_row.append(InlineKeyboardButton(
            text=f"{index + 1}/{total}",
            callback_data="noop"
        ))

        if index < total - 1:
            nav_row.append(InlineKeyboardButton(
                text="→",
                callback_data=f"nav|{state_id}|{index + 1}"
            ))

        rows.append(nav_row)

    return InlineKeyboardMarkup(inline_keyboard=rows) if rows else None


__all__ = [
    'build_host_response',
    'build_info_text',
    'create_keyboard',
    'strip_html',
]
