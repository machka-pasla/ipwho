"""In-memory state store for inline navigation between resolved IPs."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any

IP_STATE_TTL = 3600  # seconds
IP_STATE_LIMIT = 512

_ip_state_store: dict[str, dict[str, Any]] = {}


def register_ip_state(host: str, ips: list[str], extras: dict | None) -> str:
    purge_ip_states()
    state_id = _make_state_id(host, ips, extras)
    payload = {
        'host': host,
        'ips': list(ips),
        'extras': extras.copy() if extras else None,
        'created': time.time(),
    }
    existing = _ip_state_store.get(state_id)
    if existing:
        existing.update(payload)
    else:
        _ip_state_store[state_id] = payload
    return state_id


def get_ip_state(state_id: str) -> dict[str, Any] | None:
    purge_ip_states()
    state = _ip_state_store.get(state_id)
    if not state:
        return None
    if time.time() - state.get('created', 0) > IP_STATE_TTL:
        _ip_state_store.pop(state_id, None)
        return None
    state['created'] = time.time()
    return state


def purge_ip_states() -> None:
    now = time.time()
    expired = [key for key, val in _ip_state_store.items()
               if now - val.get('created', 0) > IP_STATE_TTL]
    for key in expired:
        _ip_state_store.pop(key, None)

    if len(_ip_state_store) <= IP_STATE_LIMIT:
        return

    overflow = len(_ip_state_store) - IP_STATE_LIMIT
    for key in sorted(_ip_state_store,
                      key=lambda k: _ip_state_store[k].get('created', 0))[:overflow]:
        _ip_state_store.pop(key, None)


def _make_state_id(host: str, ips: list[str], extras: dict | None) -> str:
    payload = {
        'host': (host or '').lower(),
        'ips': sorted(ips),
        'extras': _normalize_extras_for_state(extras),
        'nonce': secrets.token_hex(8),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]


def _normalize_extras_for_state(extras: dict | None) -> dict[str, Any]:
    if not extras:
        return {}
    clean = extras.copy()
    clean.pop('host', None)
    clean.pop('server', None)
    return clean


__all__ = ['get_ip_state', 'register_ip_state']
