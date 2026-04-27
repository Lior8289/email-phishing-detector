import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(https?://[^\s<>\"]+)", re.IGNORECASE)

URGENT_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
    r"\bverify\b", r"\bsuspended\b", r"\bsecurity alert\b",
    r"\btime is running out\b", r"\bact fast\b", r"\brespond now\b",
    r"\bwithin \d+ hours\b", r"\bupdate now\b",
]

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

MONEY_REQUEST_PATTERNS = [
    r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s+(?:USD|fee|payment)",
    r"\d+%\s+(?:of|commission|for your)",
    r"\bcopy of (?:passport|ID|government ID|driver)",
]

ACCOUNT_THREAT_PATTERNS = [
    r"\bproblem with (?:your|the)\s+(?:payment|account|billing)\b",
    r"\bupdate (?:your|the)\s+(?:billing|payment|card)\b",
    r"\bdelivery (?:delay|problem|issue)\b",
    r"\bverify (?:your|the)\s+(?:account|identity|payment)\b",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan", ".bid", ".racing"}

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

HOMOGLYPHS = {
    '0': 'o', '1': 'l', '3': 'e', '5': 's',
    'rn': 'm', 'vv': 'w',
}

# ── Dangerous attachment extensions ──────────────────────

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".msi", ".com", ".pif", ".hta", ".cpl",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}


# ── Helper functions ─────────────────────────────────────

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
    normalized = text.lower()
    normalized = normalized.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's')
    normalized = normalized.replace('rn', 'm').replace('vv', 'w')
    return normalized


def check_typosquatting(host: str) -> tuple[bool, str | None]:
    domain_parts = host.split('.')
    if len(domain_parts) < 2:
        return False, None
    main_domain = domain_parts[-2]
    has_suspicious_digits = bool(re.search(r'\d', main_domain))
    normalized = normalize_homoglyphs(main_domain)

    for brand, variations in BRAND_DOMAINS.items():
        for variation in variations:
            if variation in normalized and main_domain != variation:
                return True, brand
            if has_suspicious_digits and brand in main_domain.replace('0', 'o').replace('1', 'l'):
                return True, brand
            if len(main_domain) == len(variation):
                diff_count = sum(1 for a, b in zip(main_domain, variation) if a != b)
                if 1 <= diff_count <= 2:
                    return True, brand
    return False, None


def check_suspicious_domain_patterns(host: str) -> list[str]:
    issues = []
    if host.count('-') >= 2:
        issues.append("multiple_hyphens")
    if re.search(r'[a-z]\d[a-z]|\d[a-z]\d', host):
        issues.append("mixed_alphanumeric")
    domain_part = host.split('.')[0] if '.' in host else host
    if len(domain_part) > 20:
        issues.append("excessively_long")
    if re.search(r'(.)\1{3,}', host):
        issues.append("repeating_chars")
    return issues


# ── Header authentication rules ──────────────────────────

def run_header_rules(headers) -> list[dict]:
    """Analyze email authentication headers (SPF, DKIM, DMARC).
    These are the most reliable phishing indicators in real-world detection."""
    hits = []
    if headers is None:
        return hits

    # SPF check
    spf = (headers.spf or "").lower()
    if spf == "fail":
        hits.append({"id": "spf_fail", "severity": 7,
                      "message": "SPF authentication FAILED — sender IP is not authorized for this domain."})
    elif spf == "softfail":
        hits.append({"id": "spf_softfail", "severity": 4,
                      "message": "SPF soft-fail — sender IP is probably not authorized."})
    elif spf == "none":
        hits.append({"id": "spf_none", "severity": 2,
                      "message": "No SPF record found for sender domain."})

    # DKIM check
    dkim = (headers.dkim or "").lower()
    if dkim == "fail":
        hits.append({"id": "dkim_fail", "severity": 8,
                      "message": "DKIM signature verification FAILED — email may have been tampered with."})
    elif dkim == "none":
        hits.append({"id": "dkim_none", "severity": 3,
                      "message": "No DKIM signature present."})

    # DMARC check
    dmarc = (headers.dmarc or "").lower()
    if dmarc == "fail":
        hits.append({"id": "dmarc_fail", "severity": 6,
                      "message": "DMARC policy check FAILED — domain owner's policy is being violated."})
    elif dmarc == "none":
        hits.append({"id": "dmarc_none", "severity": 2,
                      "message": "No DMARC policy found for sender domain."})

    # Return-Path mismatch
    if headers.return_path:
        rp_domain = headers.return_path.split("@")[-1].lower() if "@" in headers.return_path else ""
        if rp_domain:
            # We compare against from_addr in the main run_rules function
            hits.append({"id": "_return_path_domain", "severity": 0,
                          "message": rp_domain})  # internal — used by run_rules

    # Excessive hops
    if headers.received_count is not None and headers.received_count > 10:
        hits.append({"id": "excessive_hops", "severity": 3,
                      "message": f"Email passed through {headers.received_count} servers — unusually high."})

    return hits


# ── Attachment rules ─────────────────────────────────────

def run_attachment_rules(attachments, body: str) -> list[dict]:
    """Analyze attachment metadata for dangerous file types."""
    hits = []
    if not attachments:
        return hits

    for att in attachments:
        fname = (att.filename or "").lower()

        # Double extension (e.g., invoice.pdf.exe)
        parts = fname.rsplit(".", 2)
        if len(parts) >= 3:
            final_ext = "." + parts[-1]
            if final_ext in EXECUTABLE_EXTENSIONS:
                hits.append({"id": "double_extension", "severity": 9,
                              "message": f"Double extension detected: {att.filename} — likely disguised executable."})
                continue

        # Executable
        ext = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""
        if ext in EXECUTABLE_EXTENSIONS:
            hits.append({"id": "executable_attachment", "severity": 8,
                          "message": f"Executable attachment: {att.filename}"})
        elif ext in MACRO_EXTENSIONS:
            hits.append({"id": "macro_attachment", "severity": 6,
                          "message": f"Macro-enabled document: {att.filename}"})
        elif ext in ARCHIVE_EXTENSIONS:
            # Password-protected archive hint
            if re.search(r"\bpassword\b", body, re.IGNORECASE):
                hits.append({"id": "password_protected_archive", "severity": 7,
                              "message": f"Archive attachment '{att.filename}' with password mentioned in body — common malware delivery."})
            else:
                hits.append({"id": "archive_attachment", "severity": 2,
                              "message": f"Archive attachment: {att.filename}"})

        # Suspicious MIME type mismatch
        if att.mime_type and ext:
            if ext in {".pdf"} and "pdf" not in att.mime_type.lower():
                hits.append({"id": "mime_mismatch", "severity": 5,
                              "message": f"MIME type mismatch: {att.filename} claims {att.mime_type}"})

    return hits


# ── Main rule engine ─────────────────────────────────────

def run_rules(from_addr: str, subject: str, body: str,
              headers=None, attachments=None):
    text = f"{subject}\n{body}"
    hits: list[dict] = []
    links = extract_links(text)[:20]

    # === HEADER AUTHENTICATION ===
    header_hits = run_header_rules(headers)
    # Extract return-path domain and remove the internal marker
    rp_domain = ""
    real_header_hits = []
    for h in header_hits:
        if h["id"] == "_return_path_domain":
            rp_domain = h["message"]
        else:
            real_header_hits.append(h)
    hits.extend(real_header_hits)

    # Return-Path vs From mismatch
    if rp_domain and from_addr and "@" in from_addr:
        from_domain = from_addr.split("@")[-1].lower()
        if rp_domain != from_domain:
            hits.append({"id": "return_path_mismatch", "severity": 7,
                          "message": f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})."})

    # === ATTACHMENT ANALYSIS ===
    hits.extend(run_attachment_rules(attachments, body))

    # === SENDER CHECKS ===
    if from_addr and '@' in from_addr:
        sender_domain = from_addr.split('@')[-1].lower()

        is_typosquat, brand = check_typosquatting(sender_domain)
        if is_typosquat:
            hits.append({"id": "sender_typosquatting", "severity": 9,
                          "message": f"Sender domain impersonates '{brand}': {sender_domain}"})

        domain_issues = check_suspicious_domain_patterns(sender_domain)
        if domain_issues:
            hits.append({"id": "suspicious_sender_domain", "severity": 4,
                          "message": f"Suspicious sender domain: {', '.join(domain_issues)}"})

    # === SUBJECT CHECKS ===
    if subject:
        subject_urgent = sum(1 for p in URGENT_PATTERNS if re.search(p, subject, re.IGNORECASE))
        if subject_urgent >= 1:
            hits.append({"id": "urgent_subject", "severity": 5,
                          "message": "Urgent language in subject line."})

    # === BODY TEXT ANALYSIS ===
    urgent_count = sum(1 for p in URGENT_PATTERNS if re.search(p, text, re.IGNORECASE))
    if urgent_count >= 2:
        hits.append({"id": "urgent_language", "severity": 4,
                      "message": "Multiple urgent/threatening phrases detected."})
    elif urgent_count == 1:
        hits.append({"id": "urgent_language", "severity": 2,
                      "message": "Urgent language detected."})

    threat_count = sum(1 for p in ACCOUNT_THREAT_PATTERNS if re.search(p, text, re.IGNORECASE))
    if threat_count >= 2:
        hits.append({"id": "account_threat", "severity": 5,
                      "message": "Multiple payment/account threat indicators."})
    elif threat_count == 1:
        hits.append({"id": "account_threat", "severity": 3,
                      "message": "Account/payment issue mentioned."})

    scam_count = sum(1 for p in SCAM_PATTERNS if re.search(p, text, re.IGNORECASE))
    if scam_count >= 2:
        hits.append({"id": "scam_phrases", "severity": 6,
                      "message": f"Multiple scam indicators found ({scam_count} patterns)."})
    elif scam_count == 1:
        hits.append({"id": "scam_phrases", "severity": 3,
                      "message": "Potential scam language detected."})

    money_req_count = sum(1 for p in MONEY_REQUEST_PATTERNS if re.search(p, text, re.IGNORECASE))
    if money_req_count >= 2:
        hits.append({"id": "money_request", "severity": 5,
                      "message": "Requests money and personal information."})
    elif money_req_count == 1:
        hits.append({"id": "money_request", "severity": 3,
                      "message": "Requests financial or personal details."})

    if len(text) > 50:
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
        if caps_ratio > 0.3:
            hits.append({"id": "excessive_caps", "severity": 2,
                          "message": "Excessive capitalization detected."})

    if len(re.findall(r"[!?]{3,}", text)) > 0:
        hits.append({"id": "excessive_punctuation", "severity": 2,
                      "message": "Excessive punctuation detected."})

    # === URL CHECKS ===
    for url in links:
        host = host_of(url)
        if not host:
            continue

        if is_ip_host(host):
            hits.append({"id": "ip_in_url", "severity": 5,
                          "message": f"URL uses raw IP: {url}"})

        if "xn--" in host:
            hits.append({"id": "punycode_domain", "severity": 4,
                          "message": f"Punycode domain: {host}"})

        if host in SHORTENERS:
            hits.append({"id": "url_shortener", "severity": 3,
                          "message": f"Shortened URL used: {host}"})

        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            hits.append({"id": "suspicious_tld", "severity": 4,
                          "message": f"Suspicious domain extension: {host}"})

        is_typosquat, brand = check_typosquatting(host)
        if is_typosquat:
            hits.append({"id": "typosquatting", "severity": 8,
                          "message": f"Domain impersonates '{brand}': {host}"})

        domain_issues = check_suspicious_domain_patterns(host)
        for issue in domain_issues:
            hits.append({"id": f"suspicious_domain_{issue}", "severity": 2,
                          "message": f"Suspicious domain pattern: {issue}"})

        if from_addr:
            from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ""
            if from_domain and from_domain not in host and host not in from_domain:
                for brand in BRAND_DOMAINS.keys():
                    if brand in from_domain.replace('-', '').replace('0', 'o') or brand in text.lower():
                        if brand not in host.replace('-', '').replace('0', 'o'):
                            hits.append({"id": "brand_mismatch", "severity": 6,
                                          "message": f"Claims to be from {brand} but links to {host}"})
                            break

    # === GENERIC GREETING IN SUSPICIOUS CONTEXT ===
    if re.search(r"^dear (?:friend|sir|madam|beloved|customer|user)", text, re.IGNORECASE | re.MULTILINE):
        if scam_count > 0 or money_req_count > 0 or threat_count > 0:
            hits.append({"id": "generic_greeting", "severity": 3,
                          "message": "Generic greeting with financial/threat content."})

    rules_score = min(100, sum(h["severity"] for h in hits) * 7)
    return rules_score, hits, links
