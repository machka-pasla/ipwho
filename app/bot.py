import asyncio
import logging
import hashlib
import base64
import re
import socket
import json
import ipaddress
import secrets
import time
import html
from typing import Any, Optional

import aiohttp
from aiogram import Bot, Dispatcher, types
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command
from aiogram.types import (
    InlineQuery,
    InlineQueryResultArticle,
    InputTextMessageContent,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
)
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

from .config import API_TOKEN, WEBHOOK_DOMAIN, WEBHOOK_PATH, WEBHOOK_SECRET, WEBHOOK_PORT

PROXY_SCHEMES = r'(?:vless|vmess|ss|trojan)'
DOMAIN_LABEL_PATTERN = r'(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)'
DOMAIN_PATTERN = rf'(?:{DOMAIN_LABEL_PATTERN}\.)+[A-Za-z]{2,63}'

DOH_ENDPOINT = "https://1.1.1.1/dns-query"
DNS_RECORD_TYPES = ("A", "AAAA")
DNS_HEADERS = {"Accept": "application/dns-json"}
IP_STATE_TTL = 3600  # seconds
IP_STATE_LIMIT = 512

WHOIS_TLD_MAP = {
    'ru': 'https://www.nic.ru/whois/?query={domain}',
    'su': 'https://www.nic.ru/whois/?query={domain}',
    'xn--p1ai': 'https://www.nic.ru/whois/?query={domain}',  # .рф
    'ua': 'https://hostmaster.ua/?dom={domain}',
    'by': 'https://whois.cctld.by/?request={domain}',
    'kz': 'https://whois.nic.kz/?query={domain}',
}

_ip_state_store: dict[str, dict[str, Any]] = {}

bot = Bot(token=API_TOKEN, default=DefaultBotProperties(parse_mode='HTML'))
dp = Dispatcher()


def is_ipv4(val: str) -> bool:
    return bool(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', val))


def is_ipv6(val: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, val)
        return True
    except OSError:
        return False


def is_local_ip(val: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(val)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def classify_local_ip(val: str) -> str | None:
    try:
        ip_obj = ipaddress.ip_address(val)
    except ValueError:
        return None
    if ip_obj.is_loopback:
        return "Private Network IP: Loopback"
    if ip_obj.is_link_local:
        return "Private Network IP: Link-local"
    if ip_obj.is_private:
        return "Private Network IP: Private"
    return None


def is_domain_name(val: str) -> bool:
    if is_ipv4(val) or is_ipv6(val):
        return False
    return bool(re.fullmatch(DOMAIN_PATTERN, val))


async def resolve_hostname(host: str) -> Optional[list[str]]:
    if is_ipv4(host) or is_ipv6(host):
        return [host]

    ips: list[str] = []
    seen: set[str] = set()

    async with aiohttp.ClientSession(headers=DNS_HEADERS) as session:
        for dns_type in DNS_RECORD_TYPES:
            try:
                async with session.get(
                    DOH_ENDPOINT,
                    params={'name': host, 'type': dns_type},
                    timeout=5,
                ) as resp:
                    if resp.status != 200:
                        logging.warning(
                            f"resolve_hostname DoH status {resp.status} for {host} [{dns_type}]"
                        )
                        continue
                    data = await resp.json(content_type=None)
            except Exception as e:
                logging.warning(f"resolve_hostname DoH error for {host} [{dns_type}]: {e}")
                continue

            answers = data.get('Answer') or []
            for ans in answers:
                rtype = ans.get('type')
                val = ans.get('data')
                if not val:
                    continue
                if rtype == 1 and is_ipv4(val) and val not in seen:
                    ips.append(val)
                    seen.add(val)
                elif rtype == 28 and is_ipv6(val) and val not in seen:
                    ips.append(val)
                    seen.add(val)

    return ips if ips else None


async def fetch_ip_info(ip: str) -> dict:
    url = f"http://ipwho-web:30000/json/{ip}"
    async with aiohttp.ClientSession() as s:
        try:
            async with s.get(url, timeout=10) as r:
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            logging.error(f"IP info fetch error {ip}: {e}")
            return {}




def format_org(org: str) -> str:
    parts = org.split(" ", 1)
    return f"{parts[0]} / {parts[1]}" if len(parts) == 2 else org


def parse_proxy_link(link: str) -> dict | None:
    """
    Вернуть dict: {scheme, host, port, sni}
    """
    m = re.match(r'^(?P<scheme>vless|vmess|ss|trojan)://(?P<body>.+)$',
                 link, re.I)
    if not m:
        return None
    scheme = m.group('scheme').lower()
    body = m.group('body')
    host = port = sni = None

    if scheme in ('vless', 'trojan', 'ss'):
        m2 = re.match(r'[^@]+@(?P<host>[^:/?#]+)(?::(?P<port>\d+))?'
                      r'(?:\?(?P<q>[^#]+))?', body)
        if m2:
            host = m2.group('host')
            port = m2.group('port')
            q = m2.group('q')
            if q:
                params = dict(kv.split('=', 1) for kv in q.split('&')
                              if '=' in kv)
                if params.get('security', '').lower() == 'reality':
                    sni = (params.get('sni') or params.get('serverName')
                           or params.get('server_name'))
    elif scheme == 'vmess':
        try:
            payload = body.split('#')[0].split('?')[0]
            if (pad := len(payload) % 4):
                payload += '=' * (4 - pad)
            decoded = base64.b64decode(payload).decode('utf-8',
                                                       errors='ignore')
            j = json.loads(decoded)
            host = j.get('add')
            port = str(j.get('port')) if j.get('port') else None
            sni = (j.get('sni') or j.get('serverName')
                   or j.get('server_name') or j.get('host'))
        except Exception:
            pass

    # новый дефолт: если это VLESS-Reality, но SNI не указан, берём host
    if scheme == 'vless' and host and not sni:
        sni = host

    return {'scheme': scheme, 'host': host, 'port': port, 'sni': sni} \
           if host else None


def extract_host_from_link(link: str) -> str | None:
    info = parse_proxy_link(link)
    if info:
        return info['host']
    # IPv6 в URL может быть в квадратных скобках
    m = re.search(r'https?://\[(?P<ip>[^\]]+)\]', link)
    if m:
        return m.group('ip')
    m = re.search(r'https?://(?:www\.)?([^:/?#&]+)', link)
    return m.group(1) if m else None


def normalize_host_key(host: str) -> str:
    return host.lower()


def to_punycode(domain: str) -> str:
    try:
        return domain.encode('idna').decode('ascii')
    except Exception:
        return domain


def get_registrable_domain(host: str) -> str | None:
    if not is_domain_name(host):
        return None
    puny = to_punycode(host)
    parts = puny.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return puny


def build_whois_url(host: str) -> str | None:
    domain = get_registrable_domain(host)
    if not domain:
        return None
    puny = to_punycode(domain)
    tld = puny.rsplit('.', 1)[-1].lower()
    template = WHOIS_TLD_MAP.get(tld)
    if template:
        return template.format(domain=puny)
    return f"https://who.is/whois/{puny}"


def html_escape(val: str | None) -> str:
    return html.escape(val or "", quote=True)


def strip_html(text: str) -> str:
    # naive removal, acceptable for short snippets
    no_tags = re.sub(r'<[^>]+>', '', text)
    return html.unescape(no_tags).strip()


async def parse_message_text(text: str) -> tuple[list[tuple[str, list[str]]],
                                                 dict[str, list[dict]]]:
    extras_map: dict[str, list[dict]] = {}
    for link in re.findall(fr'{PROXY_SCHEMES}://[^\s]+', text, flags=re.I):
        if (info := parse_proxy_link(link)):
            extras_map.setdefault(normalize_host_key(info['host']), []).append(info)

    domain_rx = DOMAIN_PATTERN
    items = re.findall(
        rf'{PROXY_SCHEMES}://[^\s]+|https?://[^\s]+|{domain_rx}|'
        rf'(?:\d{{1,3}}\.){{3}}\d{{1,3}}|'
        rf'(?:[A-Fa-f0-9]{{1,4}}:)+[A-Fa-f0-9]{{1,4}}',
        text)

    # Доп. поиск IPv6 (включая сокращённые формы с ::)
    for token in re.findall(r'[0-9A-Fa-f:\.]{2,}', text):
        if ':' in token and is_ipv6(token) and token not in items:
            items.append(token)

    resolved: list[tuple[str, list[str]]] = []
    seen_hosts: set[str] = set()
    for it in items:
        host = extract_host_from_link(it)
        if not host:
            if re.fullmatch(rf'({domain_rx})|(\d{{1,3}}(\.\d{{1,3}}){{3}})', it) \
               or is_ipv6(it):
                host = it
        if not host:
            continue
        norm = normalize_host_key(host)
        if norm in seen_hosts:
            continue
        if ips := await resolve_hostname(host):
            resolved.append((host, ips))
            seen_hosts.add(norm)
    return resolved, extras_map


async def build_info_text(host: str, ip: str, extras: dict | None) -> str:
    data = await fetch_ip_info(ip)
    host_safe = html_escape(host)
    whois_url = build_whois_url(host)
    lines: list[str] = []
    if whois_url:
        lines.append(f"<code>{host_safe}</code> (<a href=\"{whois_url}\">who.is</a>)")
    else:
        lines.append(f"<code>{host_safe}</code>")

    extra_lines: list[str] = []
    if extras:
        scheme = extras.get('scheme')
        port = extras.get('port')
        sni = extras.get('sni') or (host if scheme == 'vless' else None)
        if port:
            extra_lines.append(f"Port: {html_escape(str(port))}")
        if scheme:
            extra_lines.append(f"Type: {html_escape(str(scheme))}")
        if sni:
            extra_lines.append(f"SNI: {html_escape(str(sni))}")
    if extra_lines:
        lines.extend(extra_lines)

    lines.append("")
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
    mm1 = join_non_empty([
        mm.get('country_code', ''),
        mm.get('country_name', ''),
        mm.get('city_name', ''),
    ])
    if mm1:
        mm_lines.append(html_escape(mm1))
    mm2 = join_non_empty([
        mm.get('asn', ''),
        mm.get('as_desc', ''),
    ])
    if mm2:
        mm_lines.append(html_escape(mm2))

    ii_lines: list[str] = []
    cc = ii.get('country', '')
    cname = ii.get('country_name', '') if cc else ''
    ii1 = join_non_empty([
        cc,
        cname,
        ii.get('city', ''),
    ])
    if ii1:
        ii_lines.append(html_escape(ii1))
    org_val = ii.get('org', '')
    if org_val:
        ii_lines.append(html_escape(format_org(org_val)))

    if not mm1 and not ii1:
        lines.append("")
        lines.append("No geo data")
        return "\n".join(lines)

    if mm_lines:
        lines.append("")
        lines.append("MaxMind")
        lines.extend(mm_lines)
    if ii_lines:
        lines.append("")
        lines.append("IPinfo")
        lines.extend(ii_lines)

    return "\n".join(lines)


def purge_ip_states() -> None:
    now = time.time()
    expired = [key for key, val in _ip_state_store.items()
               if now - val.get('created', 0) > IP_STATE_TTL]
    for key in expired:
        _ip_state_store.pop(key, None)

    if len(_ip_state_store) <= IP_STATE_LIMIT:
        return

    overflow = len(_ip_state_store) - IP_STATE_LIMIT
    for key in sorted(_ip_state_store,
                      key=lambda k: _ip_state_store[k].get('created', 0))[:overflow]:
        _ip_state_store.pop(key, None)


def _normalize_extras_for_state(extras: dict | None) -> dict:
    if not extras:
        return {}
    clean = extras.copy()
    clean.pop('host', None)
    return clean


def _make_state_id(host: str, ips: list[str], extras: dict | None) -> str:
    payload = {
        'host': (host or '').lower(),
        'ips': sorted(ips),
        'extras': _normalize_extras_for_state(extras),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]


def register_ip_state(host: str, ips: list[str], extras: dict | None) -> str:
    purge_ip_states()
    state_id = _make_state_id(host, ips, extras)
    payload = {
        'host': host,
        'ips': list(ips),
        'extras': extras.copy() if extras else None,
        'created': time.time(),
    }
    existing = _ip_state_store.get(state_id)
    if existing:
        existing.update(payload)
    else:
        _ip_state_store[state_id] = payload
    return state_id


def get_ip_state(state_id: str) -> dict[str, Any] | None:
    purge_ip_states()
    state = _ip_state_store.get(state_id)
    if not state:
        return None
    if time.time() - state.get('created', 0) > IP_STATE_TTL:
        _ip_state_store.pop(state_id, None)
        return None
    state['created'] = time.time()
    return state


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


@dp.message(Command("start"))
async def start_handler(m: types.Message):
    await m.answer(
        "Hi!\n\nI check geo info for domains/IPs and parse vless/vmess/ss/trojan links.",
        disable_web_page_preview=True,
    )


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


@dp.callback_query()
async def ip_nav_handler(cb: types.CallbackQuery):
    data = cb.data or ""
    if not data.startswith("nav|"):
        await cb.answer()
        return
    parts = data.split("|")
    if len(parts) != 3:
        await cb.answer("Bad data", show_alert=False)
        return

    _, state_id, target_idx_raw = parts
    state = get_ip_state(state_id)
    if not state:
        await cb.answer("Expired", show_alert=False)
        return

    try:
        target_idx = int(target_idx_raw)
    except ValueError:
        await cb.answer()
        return

    ips = state.get('ips') or []
    if not ips or not (0 <= target_idx < len(ips)):
        await cb.answer()
        return

    host = state.get('host') or ''
    extras = state.get('extras')
    ip = ips[target_idx]
    logging.info(
        "Nav callback: host=%s ip=%s idx=%s/%s msg_id=%s inline_id=%s",
        host,
        ip,
        target_idx,
        len(ips),
        getattr(cb.message, 'message_id', None) if cb.message else None,
        cb.inline_message_id,
    )
    text = await build_info_text(host, ip, extras)
    nav_info = {'state_id': state_id, 'index': target_idx, 'total': len(ips)}
    keyboard = create_keyboard(host, ip, nav_info)

    try:
        if cb.message:
            await cb.message.edit_text(text,
                                       reply_markup=keyboard,
                                       parse_mode='HTML',
                                       disable_web_page_preview=True)
        elif cb.inline_message_id:
            await bot.edit_message_text(text=text,
                                        inline_message_id=cb.inline_message_id,
                                        reply_markup=keyboard,
                                        parse_mode='HTML',
                                        disable_web_page_preview=True)
    except Exception as e:
        logging.warning(f"Failed to edit message for {host}: {e}")

    await cb.answer()


@dp.message()
async def msg_handler(m: types.Message):
    if m.text is None:
        await m.answer("Unsupported message.", disable_web_page_preview=True)
        return

    txt = m.text.strip()
    is_http_url = txt.lower().startswith(("http://", "https://"))

    # ----------- Подписка -----------
    if is_http_url:
        sub_infos = await fetch_and_process_subscription(txt)
        if sub_infos:
            # Сначала показать инфо по домену подписки
            sub_host = extract_host_from_link(txt)
            if sub_host:
                res0 = await resolve_hostname(sub_host)
                if res0:
                    t0, kb0 = await build_host_response(sub_host, res0, extras=None)
                    await m.answer(t0, reply_markup=kb0, disable_web_page_preview=True)
                    await asyncio.sleep(0.35)

            for i, inf in enumerate(sub_infos):
                if (res := await resolve_hostname(inf['host'])):
                    t, kb = await build_host_response(inf['host'], res, extras=inf)
                    await m.answer(t, reply_markup=kb, disable_web_page_preview=True)
                if i < len(sub_infos) - 1:
                    await asyncio.sleep(0.35)
            return

    # ----------- Обычный текст -----------
    resolved, extras_map = await parse_message_text(txt)
    if not resolved:
        await m.answer("No domains/IPs found.", disable_web_page_preview=True)
        return

    for i, (h, ips) in enumerate(resolved):
        extras_list = extras_map.get(normalize_host_key(h))
        ex = extras_list[0] if extras_list else None
        t, kb = await build_host_response(h, ips, ex)
        await m.answer(t, reply_markup=kb, disable_web_page_preview=True)
        if len(resolved) > 1 and i < len(resolved) - 1:
            await asyncio.sleep(0.3)


@dp.inline_query()
async def inline_q(q: InlineQuery):
    query = q.query.strip()
    results: list[InlineQueryResultArticle] = []
    if not query:
        results.append(InlineQueryResultArticle(
            id="empty",
            title="Type query",
            input_message_content=InputTextMessageContent(
                message_text="Waiting for query…")
        ))
    else:
        res, extras_map = await parse_message_text(query)
        if res:
            h, ips = res[0]
            extras_list = extras_map.get(normalize_host_key(h))
            ex = extras_list[0] if extras_list else None
            txt, kb = await build_host_response(h, ips, ex)
            plain_txt = strip_html(txt)
            plain_lines = [ln for ln in plain_txt.splitlines() if ln.strip()]
            if len(plain_lines) > 1:
                desc = plain_lines[1]
            elif plain_lines:
                desc = plain_lines[0]
            else:
                desc = plain_txt
            desc = (desc or plain_txt)[:120]
            title_prefix = "Error: " if "Failed to get geo info" in plain_txt else "Info: "
            title = title_prefix + h
            rid = hashlib.sha256(f"{h}_{ips[0]}".encode()).hexdigest()[:16]
            results.append(InlineQueryResultArticle(
                id=rid,
                title=title,
                description=desc,
                input_message_content=InputTextMessageContent(
                    message_text=txt,
                    parse_mode='HTML',
                    disable_web_page_preview=True),
                reply_markup=kb
            ))
        else:
            results.append(InlineQueryResultArticle(
                id="notfound",
                title="Not found",
                input_message_content=InputTextMessageContent(
                    message_text="No IP/domain extracted.")
            ))
    await q.answer(results, cache_time=30, is_personal=False)


async def fetch_and_process_subscription(url: str) -> list[dict] | None:
    """
    Вернёт список extras-dict'ов (scheme, host, port, sni) — dups сохраняются.
    """
    headers = {
        'User-Agent': 'Happ/2.1.3/ios CFNetwork/3826.500.131 Darwin/24.5.0',
        'X-HWID': 'b16ae9eb-8434-4278-ad61-74567517091f'
    }
    try:
        async with aiohttp.ClientSession(headers=headers) as s:
            async with s.get(url, timeout=15) as r:
                if r.status != 200:
                    return None
                raw = await r.read()
    except Exception as e:
        logging.error(f"Sub fetch error {url}: {e}")
        return None

    infos: list[dict] = []

    # 1) Base64
    try:
        decoded = base64.b64decode(raw).decode('utf-8', errors='ignore')
        for link in re.findall(fr'{PROXY_SCHEMES}://[^\s]+', decoded):
            if (info := parse_proxy_link(link)):
                infos.append(info)
    except Exception:
        pass

    # 2) JSON
    try:
        data = json.loads(raw.decode('utf-8', errors='ignore'))
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    if (info := parse_proxy_link(item)):
                        infos.append(info)
                    continue
                if not isinstance(item, dict):
                    continue
                # ---- Clash / sing-box outbound ----
                outs = item.get("outbounds")
                if isinstance(outs, list):
                    for ob in outs:
                        if not isinstance(ob, dict):
                            continue
                        proto = ob.get("protocol", "").lower()
                        settings = ob.get("settings", {})
                        vnext = settings.get("vnext")
                        addr = port = None
                        if isinstance(vnext, list) and vnext and \
                                isinstance(vnext[0], dict):
                            addr = vnext[0].get("address")
                            port = str(vnext[0].get("port") or '') \
                                   if addr else None
                        elif proto in ["shadowsocks", "trojan"]:
                            srv = settings.get("servers")
                            if isinstance(srv, list) and srv and \
                                    isinstance(srv[0], dict):
                                addr = srv[0].get("address")
                                port = str(srv[0].get("port") or '') \
                                       if addr else None
                        if not addr:
                            continue
                        # ---- SNI поиск ----
                        sni = (ob.get("serverName") or ob.get("server_name")
                               or ob.get("sni") or settings.get("serverName")
                               or settings.get("server_name")
                               or settings.get("sni"))
                        if not sni:
                            ss = ob.get("streamSettings", {})
                            rs = ss.get("realitySettings", {})
                            sni = (rs.get("serverName")
                                   or rs.get("server_name")
                                   or rs.get("sni"))
                        if proto == 'vless' and not sni:
                            sni = addr
                        infos.append({'scheme': proto,
                                      'host': addr,
                                      'port': port,
                                      'sni': sni})
    except Exception:
        pass

    return infos if infos else None


async def on_startup(app: web.Application):
    if not WEBHOOK_DOMAIN:
        logging.warning("WEBHOOK_DOMAIN is not set; skipping webhook registration.")
        return
    base = WEBHOOK_DOMAIN.strip()
    if not base.startswith(('http://', 'https://')):
        base = 'https://' + base
    webhook_url = base.rstrip('/') + WEBHOOK_PATH
    try:
        webhook_kwargs = {
            'url': webhook_url,
            'allowed_updates': ["message", "inline_query", "callback_query"],
        }
        if WEBHOOK_SECRET:
            webhook_kwargs['secret_token'] = WEBHOOK_SECRET
        await bot.set_webhook(**webhook_kwargs)
        logging.info(f"Webhook set: {webhook_url}")
    except Exception as e:
        logging.error(f"Failed to set webhook: {e}")


async def on_shutdown(app: web.Application):
    try:
        await bot.delete_webhook(drop_pending_updates=False)
    except Exception:
        pass


async def healthcheck(request: web.Request) -> web.Response:
    return web.Response(text="ok")


async def run_webhook():
    if not WEBHOOK_DOMAIN:
        logging.info("WEBHOOK_DOMAIN is not configured; falling back to polling mode")
        await run_polling()
        return

    logging.info("Bot starting in webhook mode")
    app = web.Application()
    # health
    app.router.add_get('/', healthcheck)
    # webhook handler
    if WEBHOOK_SECRET:
        SimpleRequestHandler(dispatcher=dp, bot=bot, secret_token=WEBHOOK_SECRET).register(
            app, path=WEBHOOK_PATH
        )
    else:
        SimpleRequestHandler(dispatcher=dp, bot=bot).register(
            app, path=WEBHOOK_PATH
        )
    setup_application(app, dp, bot=bot)
    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)
    await web._run_app(app, host='0.0.0.0', port=WEBHOOK_PORT)


async def run_polling():
    logging.info("Bot starting in polling mode")
    try:
        await bot.delete_webhook(drop_pending_updates=True)
    except Exception:
        pass
    await dp.start_polling(bot)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    if not API_TOKEN:
        logging.critical("API_TOKEN is not set. Exiting.")
    else:
        if WEBHOOK_DOMAIN:
            asyncio.run(run_webhook())
        else:
            asyncio.run(run_polling())
