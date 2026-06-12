import re
from urllib.parse import urlparse


def check_ip_url(url: str) -> dict:
    """
    Detects if the URL uses a raw IP address instead of a domain name.
    e.g., http://192.168.1.1/login is suspicious.
    """
    hostname = urlparse(url).hostname or ""
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"  # IPv4
    )
    if ip_pattern.match(hostname):
        return {"label": "IP-based URL detected", "status": "SUSPICIOUS", "score": 2}
    return {"label": "No IP-based URL", "status": "OK", "score": 0}
