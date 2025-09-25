import os

LICENSE_KEY = os.getenv("LICENSE_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
DATA_DIR = os.getenv("DATA_DIR", "/data")

WEBHOOK_DOMAIN = os.getenv('WEBHOOK_DOMAIN')
API_TOKEN = os.getenv('API_TOKEN')
WEBHOOK_PATH = os.getenv('WEBHOOK_PATH', f'/bot/{API_TOKEN}')
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET')
WEBHOOK_PORT = int(os.getenv('WEBHOOK_PORT', '8080'))
