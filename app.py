import os
import tarfile
import shutil
import json
import requests
import logging
from flask import Flask, request, Response
import geoip2.database
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.serving import WSGIRequestHandler
import ipaddress

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

app = Flask(__name__)

GEOIP_CITY_DB = os.path.join(os.getcwd(), "GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.path.join(os.getcwd(), "GeoLite2-ASN.mmdb")
IPINFO_LITE_DB = os.path.join(os.getcwd(), "IPinfo-Lite.mmdb")

GEOIP_CITY_ARCHIVE = os.path.join(os.getcwd(), "GeoLite2-City.tar.gz")
GEOIP_ASN_ARCHIVE = os.path.join(os.getcwd(), "GeoLite2-ASN.tar.gz")

LICENSE_KEY = os.getenv("LICENSE_KEY")
IPINFO_LITE_BASE = "https://ipinfo.io/data/ipinfo_lite.mmdb"
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

city_reader = None
asn_reader = None
ipinfo_lite_reader = None


def load_databases():
    global city_reader, asn_reader
    try:
        city_reader = geoip2.database.Reader(GEOIP_CITY_DB)
        asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
        logging.info("MaxMind databases loaded.")
    except Exception as e:
        logging.error("Database load error: %s", e)


def download_db(url: str, file_path: str) -> None:
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info("Downloaded: %s", file_path)
    except Exception as e:
        logging.error("Download error %s: %s", url, e)


def extract_tar_gz(archive_path: str, extract_path: str) -> None:
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=extract_path)
        logging.info("Extracted %s to %s", archive_path, extract_path)
    except Exception as e:
        logging.error("Extract error %s: %s", archive_path, e)


def update_databases() -> None:
    url_city = (
        "https://download.maxmind.com/app/geoip_download?"
        f"edition_id=GeoLite2-City&license_key={LICENSE_KEY}&suffix=tar.gz"
    )
    url_asn = (
        "https://download.maxmind.com/app/geoip_download?"
        f"edition_id=GeoLite2-ASN&license_key={LICENSE_KEY}&suffix=tar.gz"
    )

    logging.info("Updating MaxMind databases…")
    download_db(url_city, GEOIP_CITY_ARCHIVE)
    download_db(url_asn, GEOIP_ASN_ARCHIVE)

    extract_path_city = os.path.join(os.getcwd(), "GeoLite2-City")
    extract_path_asn = os.path.join(os.getcwd(), "GeoLite2-ASN")

    os.makedirs(extract_path_city, exist_ok=True)
    os.makedirs(extract_path_asn, exist_ok=True)

    extract_tar_gz(GEOIP_CITY_ARCHIVE, extract_path_city)
    extract_tar_gz(GEOIP_ASN_ARCHIVE, extract_path_asn)

    for root, dirs, files in os.walk(extract_path_city):
        for file in files:
            if file.endswith(".mmdb"):
                new_city_db = os.path.join(root, file)
                os.replace(new_city_db, GEOIP_CITY_DB)
                logging.info("City DB updated: %s", GEOIP_CITY_DB)
                break

    for root, dirs, files in os.walk(extract_path_asn):
        for file in files:
            if file.endswith(".mmdb"):
                new_asn_db = os.path.join(root, file)
                os.replace(new_asn_db, GEOIP_ASN_DB)
                logging.info("ASN DB updated: %s", GEOIP_ASN_DB)
                break

    load_databases()
    logging.info("MaxMind update complete.")

    # Cleanup old downloaded artifacts to avoid accumulation
    try:
        if os.path.exists(GEOIP_CITY_ARCHIVE):
            os.remove(GEOIP_CITY_ARCHIVE)
        if os.path.exists(GEOIP_ASN_ARCHIVE):
            os.remove(GEOIP_ASN_ARCHIVE)
        shutil.rmtree(extract_path_city, ignore_errors=True)
        shutil.rmtree(extract_path_asn, ignore_errors=True)
        logging.info("Old downloaded DBs cleaned up.")
    except Exception as e:
        logging.warning("Cleanup error: %s", e)


def load_ipinfo_lite() -> None:
    global ipinfo_lite_reader
    try:
        if os.path.exists(IPINFO_LITE_DB):
            ipinfo_lite_reader = geoip2.database.Reader(IPINFO_LITE_DB)
            logging.info("IPinfo Lite DB loaded.")
    except Exception as e:
        logging.error("IPinfo Lite load error: %s", e)


def update_ipinfo_lite() -> None:
    url = IPINFO_LITE_BASE + (f"?token={IPINFO_TOKEN}" if IPINFO_TOKEN else "")
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        with open(IPINFO_LITE_DB, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info("IPinfo Lite DB downloaded.")
    except Exception as e:
        logging.error("IPinfo Lite download error: %s", e)
    load_ipinfo_lite()


def get_geoip_info(ip):
    try:
        response = city_reader.city(ip)
        return {
            "country_code": response.country.iso_code or "",
            "country_name": response.country.name or "",
            "city_name": response.city.name or "",
        }
    except Exception as e:
        return {"error": str(e)}


def get_asn_info(ip):
    try:
        response = asn_reader.asn(ip)
        return {
            "asn": f"AS{response.autonomous_system_number}" if response.autonomous_system_number else "",
            "as_desc": response.autonomous_system_organization or "",
        }
    except Exception as e:
        return {"error": str(e)}


def get_ipinfo_info(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        r.raise_for_status()
        data = r.json()
        return data
    except Exception as e:
        if ipinfo_lite_reader is not None:
            try:
                rec = ipinfo_lite_reader.get(ip) or {}
                return {
                    "country": rec.get("country", ""),
                    "region": rec.get("region", ""),
                    "city": rec.get("city", ""),
                    "org": rec.get("org", ""),
                    "loc": rec.get("loc", ""),
                    "postal": rec.get("postal", ""),
                    "timezone": rec.get("timezone", ""),
                }
            except Exception:
                pass
        return {"error": str(e)}


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
            cc = ipinfo.get("country", "")
            cname = geo.get("country_name", "") if cc and cc == geo.get("country_code", "") else ipinfo.get("country_name", "")
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
        cc = ipinfo.get("country", "") if isinstance(ipinfo, dict) else ""
        cname = geo.get("country_name", "") if cc and cc == geo.get("country_code", "") else (ipinfo.get("country_name", "") if isinstance(ipinfo, dict) else "")
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
        cc = ipinfo.get("country", "") if isinstance(ipinfo, dict) else ""
        cname = geo.get("country_name", "") if cc and cc == geo.get("country_code", "") else (ipinfo.get("country_name", "") if isinstance(ipinfo, dict) else "")
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


if __name__ == '__main__':
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
