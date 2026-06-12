from urllib.parse import urlparse

# Common URL shortening services
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "adf.ly", "is.gd", "cli.gs", "yfrog.com",
    "migre.me", "ff.im", "tiny.cc", "url4.eu", "tr.im",
    "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to",
    "shorturl.at", "cutt.ly", "rb.gy", "trib.al", "lnkd.in",
}


def check_shortener(url: str) -> dict:
    """
    Detects whether the URL uses a known URL shortening service.
    Shorteners can hide malicious destinations.
    """
    hostname = urlparse(url).hostname or ""
    # Strip 'www.' prefix for matching
    domain = hostname.lower().replace("www.", "")
    if domain in SHORTENERS:
        return {
            "label": f"URL shortener detected ({domain})",
            "status": "SUSPICIOUS",
            "score": 2,
        }
    return {"label": "No URL shortener detected", "status": "OK", "score": 0}
