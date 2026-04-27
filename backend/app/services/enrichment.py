"""
External reputation / enrichment checks.
Each function is designed to fail gracefully — a network timeout
should never block the scan or crash the response.
"""

import socket
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

_TIMEOUT = 3  # seconds per external check


# ── DNS MX record check ─────────────────────────────────

def check_mx(domain: str) -> dict:
    """Check if the sender domain has valid MX records.
    A domain without MX records cannot legitimately send email."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=_TIMEOUT)
        records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
        )
        return {"has_mx": True, "records": [r[1] for r in records[:5]]}
    except Exception:
        return {"has_mx": False, "records": []}


# ── Domain resolution check ─────────────────────────────

def domain_resolves(domain: str) -> bool:
    """Check whether the domain resolves to any IP address."""
    try:
        socket.setdefaulttimeout(_TIMEOUT)
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False


# ── Domain age heuristic (DNS SOA) ──────────────────────

def check_domain_soa(domain: str) -> dict | None:
    """Try to get the SOA record. While this doesn't give registration date,
    a missing SOA is suspicious for a supposedly-legitimate brand domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "SOA", lifetime=_TIMEOUT)
        soa = answers[0]
        return {
            "primary_ns": str(soa.mname).rstrip("."),
            "serial": soa.serial,
        }
    except Exception:
        return None


# ── Reverse DNS check ───────────────────────────────────

def reverse_dns(ip: str) -> str | None:
    """Attempt reverse DNS lookup on an IP address."""
    try:
        socket.setdefaulttimeout(_TIMEOUT)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


# ── Run all enrichment checks for a domain ──────────────

def enrich_domain(domain: str) -> dict:
    """Run all available enrichment checks on the sender domain.
    Returns a summary dict with results."""
    if not domain or not re.match(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$", domain):
        return {"error": "invalid domain"}

    results = {}

    with ThreadPoolExecutor(max_workers=3) as pool:
        mx_future = pool.submit(check_mx, domain)
        resolves_future = pool.submit(domain_resolves, domain)
        soa_future = pool.submit(check_domain_soa, domain)

        try:
            results["mx"] = mx_future.result(timeout=_TIMEOUT + 1)
        except (FuturesTimeout, Exception):
            results["mx"] = {"has_mx": False, "records": [], "error": "timeout"}

        try:
            results["resolves"] = resolves_future.result(timeout=_TIMEOUT + 1)
        except (FuturesTimeout, Exception):
            results["resolves"] = False

        try:
            results["soa"] = soa_future.result(timeout=_TIMEOUT + 1)
        except (FuturesTimeout, Exception):
            results["soa"] = None

    return results
