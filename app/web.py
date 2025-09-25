import os
import json
import logging
import ipaddress
from flask import Flask, request, Response
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.serving import WSGIRequestHandler

from .geoip import (
    load_databases,
    update_databases,
    load_ipinfo_lite,
    update_ipinfo_lite,
    get_geoip_info,
    get_asn_info,
    get_ipinfo_info,
)
from .country_names import get_country_name

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

app = Flask(__name__)


def classify_local_ip(addr: str) -> str | None:
    try:
        obj = ipaddress.ip_address(addr)
    except ValueError:
        return None
    if obj.is_loopback:
        return "Private Network IP: Loopback"
    if obj.is_link_local:
        return "Private Network IP: Link-local"
    if obj.is_private:
        return "Private Network IP: Private"
    return None


def resolve_ipinfo_country(ipinfo: dict | None, geo: dict) -> tuple[str, str]:
    if not isinstance(ipinfo, dict):
        return "", ""
    country_code = (ipinfo.get("country", "") or "").upper()
    if not country_code:
        return "", ""
    geo_code = (geo.get("country_code", "") or "").upper()
    if country_code == geo_code:
        country_name = geo.get("country_name", "") or get_country_name(country_code)
    else:
        country_name = ipinfo.get("country_name", "") or get_country_name(country_code)
    return country_code, country_name


def get_client_ip():
    ip = request.headers.get('X-Real-IP')
    if not ip:
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            ip = forwarded.split(',')[0].strip()
        else:
            ip = request.remote_addr
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip


def generate_text(ip, geo, asn, ipinfo, user_agent):
    def join_non_empty(parts):
        return " / ".join([p for p in parts if p])

    def is_local(addr: str) -> bool:
        try:
            obj = ipaddress.ip_address(addr)
            return obj.is_private or obj.is_loopback or obj.is_link_local
        except ValueError:
            return False

    lines = [ip, ""]

    if is_local(ip):
        label = classify_local_ip(ip) or "Private Network IP"
        lines.append(label)
        lines.append("")
    else:
        lines.append("MaxMind")
        if "error" not in geo:
            maxmind_geo = join_non_empty([
                geo.get("country_code", ""),
                geo.get("country_name", ""),
                geo.get("city_name", "")
            ])
            if maxmind_geo:
                lines.append(maxmind_geo)
        else:
            lines.append("Geo info not available")

        if "error" not in asn:
            maxmind_asn = join_non_empty([
                asn.get("asn", ""),
                asn.get("as_desc", "")
            ])
            if maxmind_asn:
                lines.append(maxmind_asn)
        else:
            lines.append("ASN info not available")

        lines.append("")

        lines.append("IPinfo")
        if "error" not in ipinfo:
            cc, cname = resolve_ipinfo_country(ipinfo, geo)
            ipinfo_geo = join_non_empty([
                cc,
                cname,
                ipinfo.get("city", "")
            ])
            if ipinfo_geo:
                lines.append(ipinfo_geo)
            org = ipinfo.get("org", "")
            if org:
                if org.startswith("AS"):
                    parts = org.split(" ", 1)
                    ipinfo_org = " / ".join(parts) if len(parts) == 2 else org
                else:
                    ipinfo_org = org
                lines.append(ipinfo_org)
        else:
            lines.append("IPinfo not available")

    lines.append("")
    lines.append(f"{user_agent}")
    lines.append("")
    lines.append("--- help ---")
    lines.append("4.ipwho.xyz --> full IPv4 info")
    lines.append("6.ipwho.xyz --> full IPv6 info")
    lines.append("4.ipwho.xyz/ip --> 1.2.3.4")
    lines.append("6.ipwho.xyz/ip --> 2001:1234:1234::1234")
    lines.append("ipwho.xyz/json --> returns your IP info in JSON")
    lines.append("ipwho.xyz/<ip> --> full IP info")
    lines.append("ipwho.xyz/json/<ip> --> specified IP info in JSON")
    lines.append("")
    lines.append("--- cli ---")
    lines.append("curl ipwho.xyz/ip --> 1.2.3.4")
    lines.append("curl ipwho.xyz/json --> {\"ip\":\"1.2.3.4\",...}")
    lines.append("curl ipwho.xyz/<ip> --> full IP info")
    lines.append("curl ipwho.xyz/json/<ip> --> specified IP info in JSON")

    return "\n".join(lines)


def get_ip_info(ip):
    user_agent = request.headers.get('User-Agent', '')
    geo = get_geoip_info(ip)
    asn = get_asn_info(ip)
    ipinfo = get_ipinfo_info(ip)
    return user_agent, geo, asn, ipinfo


@app.route('/')
def home():
    ip = get_client_ip()
    user_agent, geo, asn, ipinfo = get_ip_info(ip)
    text = generate_text(ip, geo, asn, ipinfo, user_agent) + "\n"
    return Response(text, mimetype='text/plain')


@app.route('/ip')
def ip_plain():
    ip = get_client_ip() + "\n"
    return Response(ip, mimetype='text/plain')


@app.route('/json')
def ip_json():
    ip = get_client_ip()
    user_agent, geo, asn, ipinfo = get_ip_info(ip)
    if isinstance(ipinfo, dict):
        ipinfo.pop("readme", None)
    local_label = classify_local_ip(ip)
    if local_label:
        data = {
            "ip": ip,
            "local": True,
            "local_label": local_label,
            "maxmind": {},
            "ipinfo": {},
            "user_agent": user_agent
        }
    else:
        cc, cname = resolve_ipinfo_country(ipinfo if isinstance(ipinfo, dict) else None, geo)
        data = {
            "ip": ip,
            "maxmind": {
                "country_code": geo.get("country_code", ""),
                "country_name": geo.get("country_name", ""),
                "city_name": geo.get("city_name", ""),
                "asn": asn.get("asn", ""),
                "as_desc": asn.get("as_desc", "")
            },
            "ipinfo": {
                "city": ipinfo.get("city", ""),
                "region": ipinfo.get("region", ""),
                "country": cc,
                "country_name": cname,
                "loc": ipinfo.get("loc", ""),
                "org": ipinfo.get("org", ""),
                "postal": ipinfo.get("postal", ""),
                "timezone": ipinfo.get("timezone", "")
            },
            "user_agent": user_agent
        }
    json_response = json.dumps(data, ensure_ascii=False) + "\n"
    return Response(json_response, mimetype='application/json')


@app.route('/<ip_addr>')
def ip_info(ip_addr):
    user_agent, geo, asn, ipinfo = get_ip_info(ip_addr)
    text = generate_text(ip_addr, geo, asn, ipinfo, user_agent) + "\n"
    return Response(text, mimetype='text/plain')


@app.route('/json/<ip_addr>')
def ip_json_info(ip_addr):
    user_agent, geo, asn, ipinfo = get_ip_info(ip_addr)
    if isinstance(ipinfo, dict):
        ipinfo.pop("readme", None)
    local_label = classify_local_ip(ip_addr)
    if local_label:
        data = {
            "ip": ip_addr,
            "local": True,
            "local_label": local_label,
            "maxmind": {},
            "ipinfo": {},
            "user_agent": user_agent
        }
    else:
        cc, cname = resolve_ipinfo_country(ipinfo if isinstance(ipinfo, dict) else None, geo)
        data = {
            "ip": ip_addr,
            "maxmind": {
                "country_code": geo.get("country_code", ""),
                "country_name": geo.get("country_name", ""),
                "city_name": geo.get("city_name", ""),
                "asn": asn.get("asn", ""),
                "as_desc": asn.get("as_desc", "")
            },
            "ipinfo": {
                "city": ipinfo.get("city", ""),
                "region": ipinfo.get("region", ""),
                "country": cc,
                "country_name": cname,
                "loc": ipinfo.get("loc", ""),
                "org": ipinfo.get("org", ""),
                "postal": ipinfo.get("postal", ""),
                "timezone": ipinfo.get("timezone", "")
            },
            "user_agent": user_agent
        }
    json_response = json.dumps(data, ensure_ascii=False) + "\n"
    return Response(json_response, mimetype='application/json')


class CustomRequestHandler(WSGIRequestHandler):
    def address_string(self):
        try:
            if hasattr(self, 'headers') and self.headers:
                if "X-Real-IP" in self.headers:
                    ip = self.headers["X-Real-IP"]
                elif "X-Forwarded-For" in self.headers:
                    ip = self.headers["X-Forwarded-For"].split(',')[0].strip()
                else:
                    ip = super().address_string()
            else:
                ip = super().address_string()
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            return ip
        except Exception:
            return super().address_string()

    def log_error(self, format, *args):
        return

    def log_request(self, code='-', size='-'):
        return


def create_app() -> Flask:
    return app


def run_app():
    load_databases()
    update_databases()
    update_ipinfo_lite()
    load_ipinfo_lite()

    scheduler = BackgroundScheduler()
    scheduler.add_job(update_databases, 'interval', seconds=86400)
    scheduler.add_job(update_ipinfo_lite, 'interval', seconds=86400)
    scheduler.start()

    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app.run(host='::', port=30000, request_handler=CustomRequestHandler)


if __name__ == '__main__':
    run_app()
