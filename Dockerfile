# syntax=docker/dockerfile:1.6

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app


FROM base AS web
COPY requirements/web.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt
COPY app/__init__.py app/config.py app/country_names.py app/geoip.py app/web.py ./app/
CMD ["python", "-m", "app.web"]


FROM base AS bot
COPY requirements/bot.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt
COPY app/__init__.py app/config.py app/proxy_utils.py app/bot.py ./app/
CMD ["python", "-m", "app.bot"]
