import whois
import socket
from datetime import datetime, timezone


def get_domain_age_days(domain: str) -> dict:
    """
    Looks up domain registration date via WHOIS and returns age in days.
    Returns None values if lookup fails (e.g., private/redacted WHOIS, invalid domain).
    """
    if not domain or domain.endswith(".invalid") or ".invalid" in domain or domain.count(".") == 0:
        return {"domain": domain, "age_days": None, "creation_date": None, "error": "Invalid/Internal TLD"}

    # Set socket timeout so WHOIS lookup never hangs the application
    socket.setdefaulttimeout(3.0)
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        # Some domains return a list of dates instead of a single date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {"domain": domain, "age_days": None, "creation_date": None, "error": "No creation date found"}

        # Ensure timezone-aware comparison
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days

        return {
            "domain": domain,
            "age_days": age_days,
            "creation_date": str(creation_date),
            "error": None,
        }

    except Exception as e:
        return {"domain": domain, "age_days": None, "creation_date": None, "error": str(e)}


def is_domain_suspiciously_new(age_days, threshold_days=90) -> bool:
    """Flags domains younger than the threshold (default 90 days) as suspicious."""
    if age_days is None:
        return False  # can't determine, don't penalize unfairly
    return age_days < threshold_days