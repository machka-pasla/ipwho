import tarfile
import shutil
import logging
import requests
import geoip2.database
from pathlib import Path

from .config import LICENSE_KEY, IPINFO_TOKEN, DATA_DIR
from .country_names import get_country_name

DATA_PATH = Path(DATA_DIR).expanduser().resolve()
MAXMIND_TMP_PATH = DATA_PATH / "maxmind"


def _ensure_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        logging.warning("Unable to create directory %s: %s", path, exc)


for _path in (DATA_PATH, MAXMIND_TMP_PATH):
    _ensure_directory(_path)

GEOIP_CITY_DB = DATA_PATH / "GeoLite2-City.mmdb"
GEOIP_ASN_DB = DATA_PATH / "GeoLite2-ASN.mmdb"
IPINFO_LITE_DB = DATA_PATH / "IPinfo-Lite.mmdb"

GEOIP_CITY_ARCHIVE = MAXMIND_TMP_PATH / "GeoLite2-City.tar.gz"
GEOIP_ASN_ARCHIVE = MAXMIND_TMP_PATH / "GeoLite2-ASN.tar.gz"

IPINFO_LITE_BASE = "https://ipinfo.io/data/ipinfo_lite.mmdb"

city_reader = None
asn_reader = None
ipinfo_lite_reader = None


def load_databases():
    """Load MaxMind database readers if files are available."""
    global city_reader, asn_reader

    def _open_reader(db_path: Path):
        if not db_path.exists():
            logging.warning("MaxMind database missing: %s", db_path)
            return None
        try:
            return geoip2.database.Reader(str(db_path))
        except Exception as exc:
            logging.error("Failed to open %s: %s", db_path, exc)
            return None

    city_reader = _open_reader(GEOIP_CITY_DB)
    asn_reader = _open_reader(GEOIP_ASN_DB)
    if city_reader or asn_reader:
        logging.info("MaxMind databases loaded.")


def close_databases() -> None:
    """Close open MaxMind readers to allow file replacement."""
    global city_reader, asn_reader
    for reader in (city_reader, asn_reader):
        if reader is None:
            continue
        try:
            reader.close()
        except Exception as exc:
            logging.debug("Error closing reader: %s", exc)
    city_reader = None
    asn_reader = None


def download_db(url: str, file_path: Path) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with file_path.open('wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info("Downloaded: %s", file_path)
    except Exception as e:
        logging.error("Download error %s: %s", url, e)


def _safe_extract(tar: tarfile.TarFile, target_dir: Path) -> None:
    base_path = target_dir.resolve()
    for member in tar.getmembers():
        member_path = (base_path / member.name).resolve()
        if not member_path.is_relative_to(base_path):
            raise tarfile.TarError("Refusing to extract outside target directory")
    tar.extractall(path=target_dir)


def extract_tar_gz(archive_path: Path, extract_path: Path) -> None:
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            extract_path.mkdir(parents=True, exist_ok=True)
            _safe_extract(tar, extract_path)
        logging.info("Extracted %s to %s", archive_path, extract_path)
    except Exception as e:
        logging.error("Extract error %s: %s", archive_path, e)


def update_databases() -> None:
    if not LICENSE_KEY:
        logging.error("LICENSE_KEY is not configured; cannot update MaxMind databases.")
        return

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

    if not GEOIP_CITY_ARCHIVE.exists() or not GEOIP_ASN_ARCHIVE.exists():
        logging.error("MaxMind archive download failed; aborting update.")
        return

    extract_path_city = MAXMIND_TMP_PATH / "GeoLite2-City"
    extract_path_asn = MAXMIND_TMP_PATH / "GeoLite2-ASN"

    shutil.rmtree(extract_path_city, ignore_errors=True)
    shutil.rmtree(extract_path_asn, ignore_errors=True)

    extract_tar_gz(GEOIP_CITY_ARCHIVE, extract_path_city)
    extract_tar_gz(GEOIP_ASN_ARCHIVE, extract_path_asn)

    close_databases()

    city_updated = False
    for mmdb_path in extract_path_city.rglob("*.mmdb"):
        mmdb_path.replace(GEOIP_CITY_DB)
        logging.info("City DB updated: %s", GEOIP_CITY_DB)
        city_updated = True
        break
    if not city_updated:
        logging.error("No City MMDB found in archive.")

    asn_updated = False
    for mmdb_path in extract_path_asn.rglob("*.mmdb"):
        mmdb_path.replace(GEOIP_ASN_DB)
        logging.info("ASN DB updated: %s", GEOIP_ASN_DB)
        asn_updated = True
        break
    if not asn_updated:
        logging.error("No ASN MMDB found in archive.")

    load_databases()
    logging.info("MaxMind update complete.")

    # Cleanup artifacts
    try:
        GEOIP_CITY_ARCHIVE.unlink(missing_ok=True)
        GEOIP_ASN_ARCHIVE.unlink(missing_ok=True)
        shutil.rmtree(extract_path_city, ignore_errors=True)
        shutil.rmtree(extract_path_asn, ignore_errors=True)
        logging.info("Old downloaded DBs cleaned up.")
    except Exception as e:
        logging.warning("Cleanup error: %s", e)


def load_ipinfo_lite() -> None:
    global ipinfo_lite_reader
    try:
        if IPINFO_LITE_DB.exists():
            ipinfo_lite_reader = geoip2.database.Reader(str(IPINFO_LITE_DB))
            logging.info("IPinfo Lite DB loaded.")
    except Exception as e:
        logging.error("IPinfo Lite load error: %s", e)


def update_ipinfo_lite() -> None:
    params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else None
    try:
        response = requests.get(IPINFO_LITE_BASE, params=params, stream=True, timeout=60)
        response.raise_for_status()
        with IPINFO_LITE_DB.open('wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info("IPinfo Lite DB downloaded.")
    except Exception as e:
        logging.error("IPinfo Lite download error: %s", e)
    load_ipinfo_lite()


def get_geoip_info(ip):
    if city_reader is None:
        return {"error": "City database not loaded"}
    try:
        response = city_reader.city(ip)
        country_code = response.country.iso_code or ""
        country_name = response.country.name or get_country_name(country_code)
        return {
            "country_code": country_code,
            "country_name": country_name,
            "city_name": response.city.name or "",
        }
    except Exception as e:
        return {"error": str(e)}


def get_asn_info(ip):
    if asn_reader is None:
        return {"error": "ASN database not loaded"}
    try:
        response = asn_reader.asn(ip)
        return {
            "asn": f"AS{response.autonomous_system_number}" if response.autonomous_system_number else "",
            "as_desc": response.autonomous_system_organization or "",
        }
    except Exception as e:
        return {"error": str(e)}


def get_ipinfo_info(ip):
    params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else None
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        country_code = (data.get("country") or "").upper()
        data["country"] = country_code
        if country_code and not data.get("country_name"):
            data["country_name"] = get_country_name(country_code)
        elif not country_code:
            data["country_name"] = data.get("country_name", "")
        return data
    except Exception as e:
        if ipinfo_lite_reader is not None:
            try:
                rec = ipinfo_lite_reader.get(ip) or {}
                country_code = (rec.get("country", "") or "").upper()
                return {
                    "country": country_code,
                    "country_name": get_country_name(country_code),
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
