## ipwho

Simple IP information service and Telegram bot.

- `ipwho-web`: Flask service exposing plain text and JSON IP info
- `ipwho-bot`: Telegram bot that resolves hosts/links and returns geo info

Both services run from the same Docker image and are orchestrated via Docker Compose.

### Images

Images are published to GHCR with two component tags:

- `ghcr.io/machka-pasla/ipwho:web`
- `ghcr.io/machka-pasla/ipwho:bot`

### Quick start (no repo clone)

Prerequisites: Docker and Docker Compose.

1) Network

```bash
docker network create \
  --ipv6 \
  --subnet "fd00:dead:beef:1::/64" \
  --gateway "fd00:dead:beef:1::1" \
  ipwho-network || true
```

2) Download required files:

```bash
# create a work dir
mkdir ipwho && cd ipwho

# fetch docker-compose and env example from your repo
curl -fsSL https://raw.githubusercontent.com/machka-pasla/ipwho/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/machka-pasla/ipwho/main/.env.example -o .env.example
```

3) Prepare environment:

```bash
mv .env.example .env
# edit .env and fill required values
```

4) Start services (pulls images):

```bash
docker compose up -d
```

To update later:

```bash
docker compose pull
docker compose down && docker compose up -d
```

### Environment variables

Set these in your `.env` file:

- `LICENSE_KEY`: MaxMind GeoLite2 license key (required for DB updates)
- `IPINFO_TOKEN` (optional): IPinfo token for IPinfo Lite DB downloads
- `API_TOKEN`: Telegram bot token
- `WEBHOOK_DOMAIN`: Public domain/URL reachable by Telegram (e.g. `example.com` or `https://example.com`)
- `WEBHOOK_PATH` (optional): Custom webhook path, e.g. `/bot/<token>`
- `WEBHOOK_SECRET` (optional): Secret for webhook verification
- `WEBHOOK_PORT` (default `8080`): Port the bot listens on

### Services

- `ipwho-web` (Flask)
  - Listens on port 30000 inside the container
  - Endpoints:
    - `/` plain text info
    - `/ip` plain text IP
    - `/json` JSON info for client IP
    - `/<ip>` and `/json/<ip>` info for specific IP

- `ipwho-bot` (Telegram bot)
  - Webhook mode at `WEBHOOK_DOMAIN + WEBHOOK_PATH`
  - Health check: `GET /` returns `ok`
