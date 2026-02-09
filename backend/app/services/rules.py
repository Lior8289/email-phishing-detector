import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(https?://[^\s<>\"]+)", re.IGNORECASE)

URGENT_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b",
    r"\bverify\b", r"\bsuspended\b", r"\bsecurity alert\b",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}

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

    urgent_count = sum(1 for p in URGENT_PATTERNS if re.search(p, text, re.IGNORECASE))
    if urgent_count >= 2:
        hits.append({"id": "urgent_language", "severity": 3, "message": "Urgent/threatening language detected."})

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

    rules_score = min(100, sum(h["severity"] for h in hits) * 7)
    return rules_score, hits, links
