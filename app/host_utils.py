"""Helpers for working with hosts, IPs, and DNS data."""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from typing import Any

import aiohttp

DOMAIN_LABEL_PATTERN = r'(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)'
DOMAIN_PATTERN = r'(?:' + DOMAIN_LABEL_PATTERN + r'\.)+[A-Za-z]{2,63}'

DOH_ENDPOINT = "https://1.1.1.1/dns-query"
DNS_RECORD_TYPES = ("A", "AAAA")
DNS_HEADERS = {"Accept": "application/dns-json"}

WHOIS_TLD_MAP = {
    'ru': 'https://www.nic.ru/whois/?query={domain}',
    'su': 'https://www.nic.ru/whois/?query={domain}',
    'xn--p1ai': 'https://www.nic.ru/whois/?query={domain}',  # .рф
    'ua': 'https://hostmaster.ua/?dom={domain}',
    'by': 'https://whois.cctld.by/?request={domain}',
    'kz': 'https://whois.nic.kz/?query={domain}',
}

ECH_STATUS_CACHE_TTL = 3600  # seconds
ECH_DNS_TIMEOUT = 5  # seconds
ECH_QUERY_PATTERNS = (
    ('HTTPS', lambda host: host),
    ('SVCB', lambda host: f"_443._https.{host}"),
)

_ech_status_cache: dict[str, dict[str, Any]] = {}


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
    return bool(re.fullmatch(DOMAIN_PATTERN, val))


async def resolve_hostname(host: str) -> list[str] | None:
    if is_ipv4(host) or is_ipv6(host):
        return [host]

    ips: list[str] = []
    seen: set[str] = set()

    async with aiohttp.ClientSession(headers=DNS_HEADERS) as session:
        for dns_type in DNS_RECORD_TYPES:
            try:
                async with session.get(
                    DOH_ENDPOINT,
                    params={'name': host, 'type': dns_type},
                    timeout=5,
                ) as resp:
                    if resp.status != 200:
                        logging.warning(
                            "resolve_hostname DoH status %s for %s [%s]",
                            resp.status,
                            host,
                            dns_type,
                        )
                        continue
                    data = await resp.json(content_type=None)
            except Exception as exc:
                logging.warning("resolve_hostname DoH error for %s [%s]: %s", host, dns_type, exc)
                continue

            answers = data.get('Answer') or []
            for ans in answers:
                rtype = ans.get('type')
                val = ans.get('data')
                if not val:
                    continue
                if rtype == 1 and is_ipv4(val) and val not in seen:
                    ips.append(val)
                    seen.add(val)
                elif rtype == 28 and is_ipv6(val) and val not in seen:
                    ips.append(val)
                    seen.add(val)

    return ips if ips else None


def normalize_host_key(host: str) -> str:
    return (host or '').lower()


def to_punycode(domain: str) -> str:
    try:
        return domain.encode('idna').decode('ascii')
    except Exception:
        return domain


def get_registrable_domain(host: str) -> str | None:
    if not is_domain_name(host):
        return None
    puny = to_punycode(host)
    parts = puny.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return puny


def build_whois_url(host: str) -> str | None:
    domain = get_registrable_domain(host)
    if not domain:
        return None
    puny = to_punycode(domain)
    tld = puny.rsplit('.', 1)[-1].lower()
    template = WHOIS_TLD_MAP.get(tld)
    if template:
        return template.format(domain=puny)
    return f"https://who.is/whois/{puny}"


def _make_ech_query_targets(host: str) -> list[tuple[str, str]]:
    clean_host = host.rstrip('.')
    if not clean_host:
        return []
    targets: list[tuple[str, str]] = []
    seen: set[str] = set()
    for record_type, builder in ECH_QUERY_PATTERNS:
        try:
            target = builder(clean_host)
        except Exception:
            continue
        target = (target or '').rstrip('.')
        if not target or target in seen:
            continue
        seen.add(target)
        targets.append((target, record_type))
    return targets


async def _query_ech_status(host: str) -> bool | None:
    targets = _make_ech_query_targets(host)
    if not targets:
        return None

    had_success = False
    async with aiohttp.ClientSession(headers=DNS_HEADERS) as session:
        for name, record_type in targets:
            try:
                async with session.get(
                    DOH_ENDPOINT,
                    params={'name': name, 'type': record_type},
                    timeout=ECH_DNS_TIMEOUT,
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json(content_type=None)
            except Exception as exc:
                logging.debug("ECH check DoH error for %s [%s]: %s", name, record_type, exc)
                continue

            had_success = True
            answers = data.get('Answer') or []
            found_rr = False
            for ans in answers:
                rtype = ans.get('type')
                if rtype not in (64, 65):
                    continue
                found_rr = True
                raw = ans.get('data')
                if isinstance(raw, str) and 'echconfig=' in raw.lower():
                    return True
            if found_rr:
                return False

    return False if had_success else None


async def fetch_ech_status(host: str) -> bool | None:
    if not host or not is_domain_name(host):
        return None
    puny = to_punycode(host).rstrip('.')
    if not puny:
        return None
    key = normalize_host_key(puny)
    cached = _ech_status_cache.get(key)
    now = time.time()
    if cached and now - cached.get('ts', 0) < ECH_STATUS_CACHE_TTL:
        return cached.get('status')

    status = await _query_ech_status(puny)
    if status is not None:
        _ech_status_cache[key] = {'status': status, 'ts': time.time()}
    else:
        _ech_status_cache.pop(key, None)
    return status


__all__ = [
    'DOMAIN_PATTERN',
    'build_whois_url',
    'classify_local_ip',
    'fetch_ech_status',
    'is_domain_name',
    'is_ipv4',
    'is_ipv6',
    'is_local_ip',
    'normalize_host_key',
    'resolve_hostname',
    'to_punycode',
]
