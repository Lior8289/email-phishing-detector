import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(https?://[^\s<>\"]+)", re.IGNORECASE)

URGENT_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
    r"\bverify\b", r"\bsuspended\b", r"\bsecurity alert\b",
    r"\btime is running out\b", r"\bact fast\b", r"\brespond now\b",
    r"\bwithin \d+ hours\b", r"\bupdate now\b",
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

# Account/payment issues
ACCOUNT_THREAT_PATTERNS = [
    r"\bproblem with (?:your|the)\s+(?:payment|account|billing)\b",
    r"\bupdate (?:your|the)\s+(?:billing|payment|card)\b",
    r"\bdelivery (?:delay|problem|issue)\b",
    r"\bverify (?:your|the)\s+(?:account|identity|payment)\b",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}

# Suspicious TLDs commonly used in scams
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan", ".bid", ".racing"}

# Legitimate brands to check for typosquatting
BRAND_DOMAINS = {
    "amazon": ["amazon"],
    "paypal": ["paypal"],
    "google": ["google"],
    "microsoft": ["microsoft"],
    "apple": ["apple"],
    "facebook": ["facebook"],
    "instagram": ["instagram"],
    "netflix": ["netflix"],
    "ebay": ["ebay"],
    "bank": ["bank"],
}

# Common character substitutions used in typosquatting
HOMOGLYPHS = {
    '0': 'o',  # zero -> o
    '1': 'l',  # one -> L
    '3': 'e',  # three -> e
    '5': 's',  # five -> s
    'rn': 'm', # r+n -> m
    'vv': 'w', # v+v -> w
}

def extract_links(text: str) -> list[str]:
    return URL_RE.findall(text or "")

def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""

def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))

def normalize_homoglyphs(text: str) -> str:
    """Replace common homoglyphs with their normal equivalents"""
    normalized = text.lower()
    normalized = normalized.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's')
    normalized = normalized.replace('rn', 'm').replace('vv', 'w')
    return normalized

def check_typosquatting(host: str) -> tuple[bool, str | None]:
    """Check if domain is typosquatting a known brand"""
    # Remove TLD for analysis
    domain_parts = host.split('.')
    if len(domain_parts) < 2:
        return False, None
    
    main_domain = domain_parts[-2]  # e.g., "amaz0n" from "amaz0n-orders.com"
    
    # Check for digit substitutions
    has_suspicious_digits = bool(re.search(r'\d', main_domain))
    
    # Normalize and check against known brands
    normalized = normalize_homoglyphs(main_domain)
    
    for brand, variations in BRAND_DOMAINS.items():
        for variation in variations:
            # Check if normalized version matches a brand
            if variation in normalized and main_domain != variation:
                return True, brand
            
            # Check if brand name appears with digits
            if has_suspicious_digits and brand in main_domain.replace('0', 'o').replace('1', 'l'):
                return True, brand
            
            # Check for common misspellings (edit distance of 1-2)
            if len(main_domain) == len(variation):
                diff_count = sum(1 for a, b in zip(main_domain, variation) if a != b)
                if 1 <= diff_count <= 2:
                    return True, brand
    
    return False, None

def check_suspicious_domain_patterns(host: str) -> list[str]:
    """Check for suspicious patterns in domain names"""
    issues = []
    
    # Multiple hyphens
    if host.count('-') >= 2:
        issues.append("multiple_hyphens")
    
    # Mix of numbers and letters in suspicious way
    if re.search(r'[a-z]\d[a-z]|\d[a-z]\d', host):
        issues.append("mixed_alphanumeric")
    
    # Overly long domain
    domain_part = host.split('.')[0] if '.' in host else host
    if len(domain_part) > 20:
        issues.append("excessively_long")
    
    # Repeating characters
    if re.search(r'(.)\1{3,}', host):
        issues.append("repeating_chars")
    
    return issues

def run_rules(from_addr: str, subject: str, body: str):
    text = f"{subject}\n{body}"
    hits: list[dict] = []
    links = extract_links(text)[:20]

    # === SENDER CHECKS ===
    if from_addr and '@' in from_addr:
        sender_domain = from_addr.split('@')[-1].lower()

        # Check sender domain for typosquatting
        is_typosquat, brand = check_typosquatting(sender_domain)
        if is_typosquat:
            hits.append({"id": "sender_typosquatting", "severity": 9, "message": f"Sender domain impersonates '{brand}': {sender_domain}"})

        # Check sender domain for suspicious patterns
        domain_issues = check_suspicious_domain_patterns(sender_domain)
        if domain_issues:
            hits.append({"id": "suspicious_sender_domain", "severity": 4, "message": f"Suspicious sender domain: {', '.join(domain_issues)}"})

    # === SUBJECT CHECKS ===
    # Urgent patterns in subject line are more suspicious than in body
    if subject:
        subject_urgent = sum(1 for p in URGENT_PATTERNS if re.search(p, subject, re.IGNORECASE))
        if subject_urgent >= 1:
            hits.append({"id": "urgent_subject", "severity": 5, "message": "Urgent language in subject line."})

    # Urgent language check
    urgent_count = sum(1 for p in URGENT_PATTERNS if re.search(p, text, re.IGNORECASE))
    if urgent_count >= 2:
        hits.append({"id": "urgent_language", "severity": 4, "message": "Multiple urgent/threatening phrases detected."})
    elif urgent_count == 1:
        hits.append({"id": "urgent_language", "severity": 2, "message": "Urgent language detected."})

    # Account threat patterns
    threat_count = sum(1 for p in ACCOUNT_THREAT_PATTERNS if re.search(p, text, re.IGNORECASE))
    if threat_count >= 2:
        hits.append({"id": "account_threat", "severity": 5, "message": "Multiple payment/account threat indicators."})
    elif threat_count == 1:
        hits.append({"id": "account_threat", "severity": 3, "message": "Account/payment issue mentioned."})

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
        
        # Typosquatting check (HIGH PRIORITY)
        is_typosquat, brand = check_typosquatting(host)
        if is_typosquat:
            hits.append({"id": "typosquatting", "severity": 8, "message": f"Domain impersonates '{brand}': {host}"})
        
        # Suspicious domain patterns
        domain_issues = check_suspicious_domain_patterns(host)
        for issue in domain_issues:
            hits.append({"id": f"suspicious_domain_{issue}", "severity": 2, "message": f"Suspicious domain pattern: {issue}"})
        
        # From/Link domain mismatch
        if from_addr:
            from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ""
            if from_domain and from_domain not in host and host not in from_domain:
                # Check if email claims to be from a brand but links elsewhere
                for brand in BRAND_DOMAINS.keys():
                    if brand in from_domain.replace('-', '').replace('0', 'o') or brand in text.lower():
                        if brand not in host.replace('-', '').replace('0', 'o'):
                            hits.append({"id": "brand_mismatch", "severity": 6, "message": f"Claims to be from {brand} but links to {host}"})
                            break

    # Greeting check (generic greetings are suspicious in financial contexts)
    if re.search(r"^dear (?:friend|sir|madam|beloved|customer|user)", text, re.IGNORECASE | re.MULTILINE):
        if scam_count > 0 or money_req_count > 0 or threat_count > 0:
            hits.append({"id": "generic_greeting", "severity": 3, "message": "Generic greeting with financial/threat content."})

    rules_score = min(100, sum(h["severity"] for h in hits) * 7)
    return rules_score, hits, links