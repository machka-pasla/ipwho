import os
import tarfile
import shutil
import logging
import requests
import geoip2.database

from .config import LICENSE_KEY, IPINFO_TOKEN

GEOIP_CITY_DB = os.path.join(os.getcwd(), "GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.path.join(os.getcwd(), "GeoLite2-ASN.mmdb")
IPINFO_LITE_DB = os.path.join(os.getcwd(), "IPinfo-Lite.mmdb")

GEOIP_CITY_ARCHIVE = os.path.join(os.getcwd(), "GeoLite2-City.tar.gz")
GEOIP_ASN_ARCHIVE = os.path.join(os.getcwd(), "GeoLite2-ASN.tar.gz")

IPINFO_LITE_BASE = "https://ipinfo.io/data/ipinfo_lite.mmdb"

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

    # Cleanup artifacts
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
