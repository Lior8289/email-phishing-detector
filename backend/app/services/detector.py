import math
from .rules import run_rules
from .enrichment import enrich_domain
from .storage import is_blocked, is_whitelisted, save_scan, sender_flag_count
from ..ml.loader import load_ml


def ml_probability(text: str) -> float | None:
    vectorizer, model = load_ml()
    X = vectorizer.transform([text])

    if hasattr(model, "predict_proba"):
        return float(model.predict_proba(X)[0, 1])

    if hasattr(model, "decision_function"):
        s = float(model.decision_function(X)[0])
        return 1 / (1 + math.exp(-s))

    return None


def combine(ml_p: float | None, rules_score: int) -> tuple[str, float]:
    """Combine ML probability and rules score into a final verdict.

    Weighting rationale:
    - ML (70%): trained on thousands of real phishing/ham emails, captures
      subtle patterns in language and structure.
    - Rules (30%): deterministic checks for known-bad indicators (spoofed
      headers, typosquatting, shortened URLs). These provide explainability
      and catch things the ML model may miss.
    """
    rules_p = rules_score / 100.0
    final = rules_p if ml_p is None else (0.7 * ml_p + 0.3 * rules_p)

    if final >= 0.75:
        return "Phishing", float(final)
    if final >= 0.45:
        return "Suspicious", float(final)
    return "Safe", float(1 - final)


def detect(from_addr: str, subject: str, body: str,
           headers=None, attachments=None):
    """Full detection pipeline:
    1. Check blocklist/whitelist
    2. Run rules engine (content + headers + attachments)
    3. Run ML inference
    4. Enrich sender domain via DNS
    5. Combine scores → verdict
    6. Save to scan history
    """
    text = f"{subject}\n{body}".strip()

    # ── Blocklist / Whitelist check ──
    sender_domain = ""
    blocklist_hit = False
    if from_addr and "@" in from_addr:
        sender_domain = from_addr.split("@")[-1].lower()
        if is_blocked(sender_domain) or is_blocked(from_addr.lower()):
            blocklist_hit = True
        if is_whitelisted(sender_domain) or is_whitelisted(from_addr.lower()):
            # Whitelisted — still scan but skip auto-flag
            pass

    # ── Rules engine ──
    rules_score, hits, links = run_rules(from_addr, subject, body,
                                          headers=headers,
                                          attachments=attachments)

    # ── ML inference ──
    ml_p = ml_probability(text)

    # ── External enrichment ──
    enrichment = None
    if sender_domain:
        enrichment_data = enrich_domain(sender_domain)
        enrichment = enrichment_data

        # No MX record → suspicious
        mx_info = enrichment_data.get("mx", {})
        if mx_info and not mx_info.get("has_mx"):
            hits.append({"id": "no_mx_record", "severity": 5,
                          "message": f"Sender domain '{sender_domain}' has no MX records — cannot receive email."})
            rules_score = min(100, rules_score + 35)

        # Domain doesn't resolve
        if enrichment_data.get("resolves") is False:
            hits.append({"id": "domain_unresolvable", "severity": 6,
                          "message": f"Sender domain '{sender_domain}' does not resolve — likely fake."})
            rules_score = min(100, rules_score + 42)

    # ── Combine ──
    label, conf = combine(ml_p, rules_score)

    # Blocklist override
    if blocklist_hit and label == "Safe":
        label = "Suspicious"
        conf = max(conf, 0.5)
        hits.insert(0, {"id": "blocklist_hit", "severity": 10,
                         "message": f"Sender is on your personal blocklist."})

    # ── Sender history ──
    prior_flags = sender_flag_count(from_addr) if from_addr else 0

    # ── Persist to history ──
    save_scan(from_addr, subject, label, conf, rules_score, hits)

    return {
        "classification": label,
        "confidence": conf,
        "ml_probability": ml_p,
        "rules_score": rules_score,
        "rule_hits": hits,
        "extracted_links": links,
        "enrichment": enrichment,
        "sender_history": {"times_flagged": prior_flags} if from_addr else None,
        "blocklist_hit": blocklist_hit,
    }
