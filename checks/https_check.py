from urllib.parse import urlparse


def check_https(url: str) -> dict:
    """
    Checks whether the URL uses HTTPS. HTTP-only URLs are flagged as suspicious
    since they transmit data in plaintext.
    """
    scheme = urlparse(url).scheme
    if scheme != "https":
        return {"label": "No HTTPS detected (uses HTTP)", "status": "SUSPICIOUS", "score": 1}
    return {"label": "HTTPS is present", "status": "OK", "score": 0}
