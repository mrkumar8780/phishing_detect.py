import re
from urllib.parse import urlparse

# Legitimate brands commonly spoofed in phishing attacks
TRUSTED_BRANDS = [
    "paypal", "apple", "amazon", "google", "facebook", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "ebay", "yahoo", "chase", "wellsfargo", "citibank", "bankofamerica",
    "irs", "usps", "fedex", "dhl",
]

# Lookalike substitution patterns: digit replacing a letter is suspicious
# e.g., paypa1.com (1 instead of l), g00gle.com (0 instead of o)
# We only flag numeric digits that appear where letters are expected,
# specifically 0 used in place of 'o' and 1 used in place of 'l' or 'i'.
LOOKALIKE_PATTERN = re.compile(r"(?<=[a-z])[01]|[01](?=[a-z])")


def _has_lookalike_chars(domain: str) -> bool:
    """Checks if a domain uses digit substitutions inside word characters (e.g. paypa1.com)."""
    # Remove the TLD portion for cleaner analysis
    name_part = domain.rsplit(".", 1)[0]
    return bool(LOOKALIKE_PATTERN.search(name_part))


def _spoofs_brand(domain: str) -> bool:
    """
    Checks if the domain contains a trusted brand name but is NOT the real domain.
    e.g., 'paypal-login-secure.com' contains 'paypal' but it's not 'paypal.com'.
    """
    for brand in TRUSTED_BRANDS:
        if brand in domain:
            # The real domain would be just brand.com (or brand.net etc.)
            # If there's extra text around the brand name, it's suspicious
            if not re.match(rf"^(www\.)?{brand}\.(com|net|org|io|co)$", domain):
                return True
    return False


def check_domain(url: str) -> dict:
    """
    Detects suspicious or lookalike domains that mimic legitimate brands.
    """
    hostname = urlparse(url).hostname or ""
    domain = hostname.lower().replace("www.", "")

    if _spoofs_brand(domain):
        return {
            "label": f"Suspicious lookalike domain detected ({domain})",
            "status": "DANGEROUS",
            "score": 3,
        }
    if _has_lookalike_chars(domain):
        return {
            "label": f"Lookalike characters in domain ({domain})",
            "status": "SUSPICIOUS",
            "score": 2,
        }
    return {"label": "Domain looks legitimate", "status": "OK", "score": 0}
