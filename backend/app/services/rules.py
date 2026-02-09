import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(https?://[^\s<>\"]+)", re.IGNORECASE)

URGENT_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
    r"\bverify\b", r"\bsuspended\b", r"\bsecurity alert\b",
    r"\btime is running out\b", r"\bact fast\b", r"\brespond now\b",
]

# Common scam phrases
SCAM_PATTERNS = [
    r"\bprince\b", r"\binheritance\b", r"\bmillion\s+(?:dollars|USD|EUR|GBP)\b",
    r"\b(?:foreign|security)\s+vault\b", r"\bprocessing fee\b",
    r"\b100%\s+(?:risk\s+free|legal|safe|guaranteed)\b",
    r"\bwestern union\b", r"\bmoney\s+gram\b",
    r"\bbank\s+account\s+(?:number|details)\b",
    r"\bclaim\s+(?:your|the)\s+(?:prize|funds|money)\b",
    r"\bunclaimed\s+(?:funds|money|inheritance)\b",
    r"\bgod\s+bless\b.*(?:urgent|help|transfer)",
]

# Suspicious financial patterns
MONEY_REQUEST_PATTERNS = [
    r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s+(?:USD|fee|payment)",
    r"\d+%\s+(?:of|commission|for your)",
    r"\bcopy of (?:passport|ID|government ID|driver)",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}

# Suspicious TLDs commonly used in scams
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan"}

def extract_links(text: str) -> list[str]:
    return URL_RE.findall(text or "")

def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""

def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))

def run_rules(from_addr: str, subject: str, body: str):
    text = f"{subject}\n{body}"
    hits: list[dict] = []
    links = extract_links(text)[:20]

    # Urgent language check
    urgent_count = sum(1 for p in URGENT_PATTERNS if re.search(p, text, re.IGNORECASE))
    if urgent_count >= 2:
        hits.append({"id": "urgent_language", "severity": 3, "message": "Urgent/threatening language detected."})

    # Scam phrase check
    scam_count = sum(1 for p in SCAM_PATTERNS if re.search(p, text, re.IGNORECASE))
    if scam_count >= 2:
        hits.append({"id": "scam_phrases", "severity": 6, "message": f"Multiple scam indicators found ({scam_count} patterns)."})
    elif scam_count == 1:
        hits.append({"id": "scam_phrases", "severity": 3, "message": "Potential scam language detected."})

    # Money/personal info request check
    money_req_count = sum(1 for p in MONEY_REQUEST_PATTERNS if re.search(p, text, re.IGNORECASE))
    if money_req_count >= 2:
        hits.append({"id": "money_request", "severity": 5, "message": "Requests money and personal information."})
    elif money_req_count == 1:
        hits.append({"id": "money_request", "severity": 3, "message": "Requests financial or personal details."})

    # Excessive capitalization check
    if len(text) > 50:
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
        if caps_ratio > 0.3:
            hits.append({"id": "excessive_caps", "severity": 2, "message": "Excessive capitalization detected."})

    # Excessive punctuation (!!!, ???)
    if len(re.findall(r"[!?]{3,}", text)) > 0:
        hits.append({"id": "excessive_punctuation", "severity": 2, "message": "Excessive punctuation detected."})

    # URL checks
    for url in links:
        host = host_of(url)
        if not host:
            continue
        
        if is_ip_host(host):
            hits.append({"id": "ip_in_url", "severity": 5, "message": f"URL uses raw IP: {url}"})
        
        if "xn--" in host:
            hits.append({"id": "punycode_domain", "severity": 4, "message": f"Punycode domain: {host}"})
        
        if host in SHORTENERS:
            hits.append({"id": "url_shortener", "severity": 3, "message": f"Shortened URL used: {host}"})
        
        # Check for suspicious TLDs
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            hits.append({"id": "suspicious_tld", "severity": 4, "message": f"Suspicious domain extension: {host}"})
        
        # Domain-message mismatch (e.g., claims to be from bank but uses random domain)
        if any(brand in text.lower() for brand in ["paypal", "bank", "amazon", "apple", "microsoft"]):
            if not any(brand in host for brand in ["paypal", "bank", "amazon", "apple", "microsoft"]):
                hits.append({"id": "brand_mismatch", "severity": 5, "message": "Message mentions brand but link doesn't match."})

    # Greeting check (generic greetings are suspicious in financial contexts)
    if re.search(r"^dear (?:friend|sir|madam|beloved)", text, re.IGNORECASE | re.MULTILINE):
        if scam_count > 0 or money_req_count > 0:
            hits.append({"id": "generic_greeting", "severity": 3, "message": "Generic greeting with financial request."})

    rules_score = min(100, sum(h["severity"] for h in hits) * 7)
    return rules_score, hits, links