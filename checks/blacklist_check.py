import os
from urllib.parse import urlparse

# Path to the blacklist file relative to this module
_BLACKLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "blacklist.txt")


def _load_blacklist(path: str) -> set:
    """Loads blacklisted domains from a text file (one domain per line)."""
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


def check_blacklist(url: str) -> dict:
    """
    Compares the URL's domain against a local blacklist of known phishing domains.
    """
    hostname = urlparse(url).hostname or ""
    domain = hostname.lower().replace("www.", "")
    blacklist = _load_blacklist(_BLACKLIST_PATH)

    if domain in blacklist:
        return {
            "label": f"Domain '{domain}' found in blacklist",
            "status": "DANGEROUS",
            "score": 4,
        }
    return {"label": "Domain not in blacklist", "status": "OK", "score": 0}
