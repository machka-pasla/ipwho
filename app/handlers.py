"""Aiogram handler registration."""
from __future__ import annotations

import asyncio
import hashlib
import logging

from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import (
    InlineQuery,
    InlineQueryResultArticle,
    InputTextMessageContent,
)

from .host_utils import normalize_host_key, resolve_hostname
from .ip_state import get_ip_state
from .parser import parse_message_text
from .proxies import extract_host_from_link
from .responses import build_host_response, build_info_text, create_keyboard, strip_html
from .subscription import fetch_subscription_entries


def register_handlers(dp: Dispatcher, bot: Bot) -> None:
    @dp.message(Command("start"))
    async def start_handler(m: types.Message):
        await m.answer(
            "Hi!\n\nI check geo info for domains/IPs and parse vless/vmess/ss/trojan links.",
            disable_web_page_preview=True,
        )

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
        except Exception as exc:
            logging.warning("Failed to edit message for %s: %s", host, exc)

        await cb.answer()

    @dp.message()
    async def msg_handler(m: types.Message):
        if m.text is None:
            await m.answer("Unsupported message.", disable_web_page_preview=True)
            return

        txt = m.text.strip()
        is_http_url = txt.lower().startswith(("http://", "https://"))
        sent_hosts: set[str] = set()

        if is_http_url:
            sub_host = extract_host_from_link(txt)
            if sub_host:
                norm_sub_host = normalize_host_key(sub_host)
                if norm_sub_host not in sent_hosts:
                    res0 = await resolve_hostname(sub_host)
                    if res0:
                        t0, kb0 = await build_host_response(sub_host, res0, extras=None)
                        await m.answer(t0, reply_markup=kb0, disable_web_page_preview=True)
                        sent_hosts.add(norm_sub_host)
                        await asyncio.sleep(0.35)

            sub_infos = await fetch_subscription_entries(txt)
            if sub_infos:
                for i, info in enumerate(sub_infos):
                    server = info.get('server')
                    if not server:
                        continue
                    if (resolved := await resolve_hostname(server)):
                        t, kb = await build_host_response(server, resolved, extras=info)
                        await m.answer(t, reply_markup=kb, disable_web_page_preview=True)
                    if i < len(sub_infos) - 1:
                        await asyncio.sleep(0.35)
                return

        resolved, extras_map = await parse_message_text(txt)
        filtered_resolved: list[tuple[str, list[str]]] = []
        for host, ips in resolved:
            if normalize_host_key(host) in sent_hosts:
                continue
            filtered_resolved.append((host, ips))

        if not filtered_resolved:
            if sent_hosts:
                return
            await m.answer("No domains/IPs found.", disable_web_page_preview=True)
            return

        for idx, (host, ips) in enumerate(filtered_resolved):
            extras_list = extras_map.get(normalize_host_key(host))
            extras = extras_list[0] if extras_list else None
            text, kb = await build_host_response(host, ips, extras)
            await m.answer(text, reply_markup=kb, disable_web_page_preview=True)
            sent_hosts.add(normalize_host_key(host))
            if len(filtered_resolved) > 1 and idx < len(filtered_resolved) - 1:
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
                host, ips = res[0]
                extras_list = extras_map.get(normalize_host_key(host))
                extras = extras_list[0] if extras_list else None
                txt, kb = await build_host_response(host, ips, extras)
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
                title = title_prefix + host
                rid = hashlib.sha256(f"{host}_{ips[0]}".encode()).hexdigest()[:16]
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


__all__ = ['register_handlers']
