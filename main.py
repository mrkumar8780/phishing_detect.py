"""
Phishing Detection Tool
-----------------------
Usage:  python main.py --url <URL>
Example: python main.py --url http://192.168.1.1/login
"""

import argparse
import sys
from urllib.parse import urlparse

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA = True
except ImportError:
    COLORAMA = False

from checks.ip_check import check_ip_url
from checks.https_check import check_https
from checks.length_check import check_url_length
from checks.shortener_check import check_shortener
from checks.blacklist_check import check_blacklist
from checks.domain_check import check_domain


# ── Colour helpers ──────────────────────────────────────────────────────────

def _colour(text: str, status: str) -> str:
    if not COLORAMA:
        return text
    mapping = {
        "OK":        Fore.GREEN,
        "SUSPICIOUS": Fore.YELLOW,
        "DANGEROUS": Fore.RED,
        "ERROR":     Fore.RED,
    }
    return mapping.get(status, "") + text + Style.RESET_ALL


def _icon(status: str) -> str:
    return {
        "OK":        "[✓]",
        "SUSPICIOUS": "[!]",
        "DANGEROUS": "[✗]",
        "ERROR":     "[✗]",
    }.get(status, "[ ]")


# ── URL validation ───────────────────────────────────────────────────────────

def validate_url(url: str) -> bool:
    """Returns True if the URL has a valid scheme and netloc."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


# ── Verdict logic ────────────────────────────────────────────────────────────

def compute_verdict(total_score: int) -> tuple:
    """Map cumulative risk score → (verdict label, status string)."""
    if total_score == 0:
        return "SAFE", "OK"
    elif total_score <= 3:
        return "SUSPICIOUS", "SUSPICIOUS"
    else:
        return "DANGEROUS", "DANGEROUS"


# ── Main ─────────────────────────────────────────────────────────────────────

def analyse(url: str) -> None:
    print()
    print(f"  Analysing: {url}")
    print("  " + "─" * 55)

    # Run all checks
    checks = [
        check_ip_url(url),
        check_https(url),
        check_url_length(url),
        check_shortener(url),
        check_blacklist(url),
        check_domain(url),
    ]

    total_score = 0
    for result in checks:
        status = result["status"]
        label  = result["label"]
        score  = result.get("score", 0)
        total_score += score

        icon = _icon(status)
        line = f"  {icon} {label:<50} → {status}"
        print(_colour(line, status))

    print("  " + "─" * 55)

    verdict, verdict_status = compute_verdict(total_score)
    verdict_line = f"\n  Final Verdict: {verdict}  (risk score: {total_score})\n"
    print(_colour(verdict_line, verdict_status))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Analyses a URL for phishing indicators.",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="The URL to analyse (e.g. https://example.com)",
    )
    args = parser.parse_args()
    url = args.url.strip()

    if not validate_url(url):
        error = f"  [✗] Error: '{url}' is not a valid URL. Include http:// or https://"
        print(_colour(error, "ERROR"))
        sys.exit(1)

    analyse(url)


if __name__ == "__main__":
    main()
