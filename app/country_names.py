"""Country name lookup utilities with Kosovo support."""

from functools import lru_cache
from typing import Optional

try:
    import pycountry  # type: ignore
except ImportError:  # pragma: no cover - optional dependency safeguard
    pycountry = None  # type: ignore[assignment]


COUNTRY_OVERRIDES: dict[str, str] = {
    "XK": "Kosovo",
    "UK": "United Kingdom",
}


def _lookup_pycountry(alpha2: str) -> Optional[str]:
    if not pycountry:
        return None
    try:
        country = pycountry.countries.get(alpha_2=alpha2)
    except (AttributeError, KeyError, LookupError):
        country = None
    if not country:
        return None
    return (
        getattr(country, "common_name", None)
        or getattr(country, "official_name", None)
        or getattr(country, "name", None)
    )


@lru_cache(maxsize=None)
def get_country_name(alpha2: Optional[str]) -> str:
    """Return full country name for an ISO Alpha-2 code."""
    if not alpha2:
        return ""
    code = alpha2.strip().upper()
    if not code:
        return ""

    if code in COUNTRY_OVERRIDES:
        return COUNTRY_OVERRIDES[code]

    name = _lookup_pycountry(code)
    if name:
        return name

    # Fallback to an empty string when nothing matches.
    return ""

