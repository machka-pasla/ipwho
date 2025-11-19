"""Bot entrypoint with dispatcher setup."""

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

from .config import API_TOKEN, WEBHOOK_DOMAIN, WEBHOOK_PATH, WEBHOOK_SECRET, WEBHOOK_PORT
from .handlers import register_handlers

bot = Bot(token=API_TOKEN, default=DefaultBotProperties(parse_mode='HTML'))
dp = Dispatcher()
register_handlers(dp, bot)


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
        logging.info("Webhook set: %s", webhook_url)
    except Exception as exc:
        logging.error("Failed to set webhook: %s", exc)


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
    app.router.add_get('/', healthcheck)
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
