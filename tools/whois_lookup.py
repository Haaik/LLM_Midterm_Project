import re
import whois
from datetime import datetime
from typing import Optional


def _extract_domain(url: str) -> str:
    domain = re.sub(r"https?://", "", url, flags=re.IGNORECASE)
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    # Strip port
    domain = domain.split(":")[0]
    # Strip www.
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower().strip()


def _domain_age_days(creation_date) -> Optional[int]:
    if creation_date is None:
        return None
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(creation_date, datetime):
        return (datetime.utcnow() - creation_date).days
    return None


def whois_lookup(url: str) -> dict:
    domain = _extract_domain(url)
    try:
        w = whois.whois(domain)
        age = _domain_age_days(w.creation_date)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "domain_age_days": age,
            "country": w.country,
            "name_servers": w.name_servers[:3] if w.name_servers else None,
            "status": w.status if isinstance(w.status, str) else (w.status[0] if w.status else None),
        }
    except Exception as exc:
        return {"domain": domain, "error": str(exc)}
