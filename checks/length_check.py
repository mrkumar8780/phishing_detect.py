def check_url_length(url: str, threshold: int = 75) -> dict:
    """
    Flags abnormally long URLs. URLs longer than `threshold` characters
    are common in phishing attempts to obfuscate the real destination.
    """
    if len(url) > threshold:
        return {
            "label": f"URL length is {len(url)} chars (>{threshold})",
            "status": "SUSPICIOUS",
            "score": 1,
        }
    return {"label": f"URL length is normal ({len(url)} chars)", "status": "OK", "score": 0}
