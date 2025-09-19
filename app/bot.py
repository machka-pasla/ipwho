import asyncio
import logging
import hashlib
import base64
import re
import socket
import json
import ipaddress
from typing import Optional

import aiohttp
from aiogram import Bot, Dispatcher, types
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

bot = Bot(token=API_TOKEN)
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
    return bool(re.fullmatch(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', val))


async def resolve_hostname(host: str) -> Optional[tuple[str, str]]:
    loop = asyncio.get_running_loop()
    if is_ipv4(host) or is_ipv6(host):
        return host, host
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, family=socket.AF_UNSPEC,
                             type=socket.SOCK_STREAM),
            timeout=5.0)
        if not infos:
            return None
        for fam, *_ , sockaddr in infos:
            if fam == socket.AF_INET:
                return host, sockaddr[0]
        return host, infos[0][4][0]
    except Exception as e:
        logging.warning(f"resolve_hostname error for {host}: {e}")
        return None


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


async def parse_message_text(text: str) -> tuple[list[tuple[str, str]],
                                                 dict[str, list[dict]]]:
    extras_map: dict[str, list[dict]] = {}
    for link in re.findall(fr'{PROXY_SCHEMES}://[^\s]+', text, flags=re.I):
        if (info := parse_proxy_link(link)):
            extras_map.setdefault(info['host'], []).append(info)

    domain_rx = (r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
                 r'[A-Za-z]{2,63}')
    items = re.findall(
        rf'{PROXY_SCHEMES}://[^\s]+|https?://[^\s]+|{domain_rx}|'
        rf'(?:\d{{1,3}}\.){{3}}\d{{1,3}}|'
        rf'(?:[A-Fa-f0-9]{{1,4}}:)+[A-Fa-f0-9]{{1,4}}',
        text)

    # Доп. поиск IPv6 (включая сокращённые формы с ::)
    for token in re.findall(r'[0-9A-Fa-f:\.]{2,}', text):
        if ':' in token and is_ipv6(token) and token not in items:
            items.append(token)

    resolved: list[tuple[str, str]] = []
    for it in items:
        host = extract_host_from_link(it)
        if not host:
            if re.fullmatch(rf'({domain_rx})|(\d{{1,3}}(\.\d{{1,3}}){{3}})', it) \
               or is_ipv6(it):
                host = it
        if host and (res := await resolve_hostname(host)):
            resolved.append(res)
    return resolved, extras_map


async def build_info_text(host: str, ip: str, extras: dict | None,
                          include_links: bool) -> str:
    """
    Сформировать итоговый plain-текст.
    """
    data = await fetch_ip_info(ip)
    if not data:
        return f"Failed to get info for {host} ({ip})"

    header = host if host == ip or is_ipv4(host) or is_ipv6(host) \
        else f"{host} ({ip})"

    # --- доп-инфо: порт, тип, SNI ---
    if extras:
        # автозаполнение SNI для VLESS, если не пришло
        if extras.get('scheme') == 'vless' and not extras.get('sni'):
            extras['sni'] = host
        lines = []
        if extras.get('port'):
            lines.append(f"Port: {extras['port']}")
        if extras.get('scheme'):
            lines.append(f"Type: {extras['scheme']}")
        if extras.get('sni'):
            lines.append(f"SNI: {extras['sni']}")
        if lines:
            header = f"{header}\n" + "\n".join(lines)

    def join_non_empty(parts: list[str]) -> str:
        return " / ".join([p for p in parts if p])

    mm = data.get("maxmind", {})
    ii = data.get("ipinfo", {})
    local = is_local_ip(ip)

    if local:
        local_label = classify_local_ip(ip) or "Private Network IP"
        return f"{header}\n\n{local_label}"

    mm_lines: list[str] = []
    ii_lines: list[str] = []

    mm1 = join_non_empty([
        mm.get('country_code', ''),
        mm.get('country_name', ''),
        mm.get('city_name', ''),
    ])
    if mm1:
        mm_lines.append(mm1)
    mm2 = join_non_empty([
        mm.get('asn', ''),
        mm.get('as_desc', ''),
    ])
    if mm2:
        mm_lines.append(mm2)

    cc = ii.get('country', '')
    cname = ii.get('country_name', '')
    ii1 = join_non_empty([
        cc,
        cname,
        ii.get('city', ''),
    ])
    if ii1:
        ii_lines.append(ii1)
    org_val = ii.get('org', '')
    if org_val:
        ii_lines.append(format_org(org_val))

    txt = f"{header}\n\n"
    if mm_lines:
        txt += "MaxMind\n" + "\n".join(mm_lines) + "\n\n"
    if ii_lines:
        txt += "IPinfo\n" + "\n".join(ii_lines)
    return txt


@dp.message(Command("start"))
async def start_handler(m: types.Message):
    await m.answer(
        "Hi!\n\nI check geo info for domains/IPs and parse vless/vmess/ss/trojan links."
    )


def create_keyboard(host: str, ip: str) -> InlineKeyboardMarkup | None:
    if is_local_ip(ip):
        return None
    rows: list[list[InlineKeyboardButton]] = []
    rows.extend([
        [InlineKeyboardButton(text="BGP", url=f"https://bgp.tools/search?q={ip}")],
        [InlineKeyboardButton(text="Censys", url=f"https://search.censys.io/hosts/{ip}")],
        [InlineKeyboardButton(text="IPinfo", url=f"https://ipinfo.io/{ip}")],
    ])
    if is_domain_name(host):
        rows.append([InlineKeyboardButton(text="WHOIS", url=f"https://who.is/whois/{host}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


@dp.message()
async def msg_handler(m: types.Message):
    if m.text is None:
        await m.answer("Unsupported message.")
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
                    t0 = await build_info_text(res0[0], res0[1],
                                               extras=None,
                                               include_links=False)
                    await m.answer(t0, reply_markup=create_keyboard(res0[0], res0[1]))
                    await asyncio.sleep(0.35)

            for i, inf in enumerate(sub_infos):
                if (res := await resolve_hostname(inf['host'])):
                    t = await build_info_text(res[0], res[1],
                                              extras=inf,
                                              include_links=False)
                    await m.answer(t, reply_markup=create_keyboard(res[0], res[1]))
                if i < len(sub_infos) - 1:
                    await asyncio.sleep(0.35)
            return

    # ----------- Обычный текст -----------
    resolved, extras_map = await parse_message_text(txt)
    if not resolved:
        await m.answer("No domains/IPs found.")
        return

    if len(resolved) == 1:
        h, ip = resolved[0]
        ex = extras_map.get(h, [None])[0] if extras_map.get(h) else None
        t = await build_info_text(h, ip, ex, include_links=False)
        await m.answer(t, reply_markup=create_keyboard(h, ip))
    else:
        for i, (h, ip) in enumerate(resolved):
            ex = extras_map.get(h, [None])[0] if extras_map.get(h) else None
            t = await build_info_text(h, ip, ex, include_links=False)
            await m.answer(t, reply_markup=create_keyboard(h, ip))
            if i < len(resolved) - 1:
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
            h, ip = res[0]
            ex = extras_map.get(h, [None])[0] if extras_map.get(h) else None
            txt = await build_info_text(h, ip, ex, include_links=False)
            title = ("Info: " if "Failed" not in txt else "Error: ") + h
            desc = txt.split('\n\n')[1].split('\n')[0] if '\n\n' in txt else txt
            rid = hashlib.sha256(f"{h}_{ip}".encode()).hexdigest()[:16]
            results.append(InlineQueryResultArticle(
                id=rid,
                title=title,
                description=desc,
                input_message_content=InputTextMessageContent(
                    message_text=txt),
                reply_markup=create_keyboard(h, ip)
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
        logging.error("WEBHOOK_DOMAIN is not set.")
        return
    base = WEBHOOK_DOMAIN.strip()
    if not base.startswith(('http://', 'https://')):
        base = 'https://' + base
    webhook_url = base.rstrip('/') + WEBHOOK_PATH
    try:
        if WEBHOOK_SECRET:
            await bot.set_webhook(url=webhook_url, secret_token=WEBHOOK_SECRET)
        else:
            await bot.set_webhook(url=webhook_url)
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


async def run_bot():
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


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    if not API_TOKEN:
        logging.critical("API_TOKEN is not set. Exiting.")
    else:
        asyncio.run(run_bot())
