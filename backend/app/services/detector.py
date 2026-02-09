import math
from .rules import run_rules
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
    rules_p = rules_score / 100.0
    final = rules_p if ml_p is None else (0.7 * ml_p + 0.3 * rules_p)

    if final >= 0.75:
        return "Phishing", float(final)
    if final >= 0.45:
        return "Suspicious", float(final)
    return "Safe", float(1 - final)

def detect(from_addr: str, subject: str, body: str):
    text = f"{subject}\n{body}".strip()
    rules_score, hits, links = run_rules(from_addr, subject, body)
    ml_p = ml_probability(text)
    label, conf = combine(ml_p, rules_score)

    return {
        "classification": label,
        "confidence": conf,
        "ml_probability": ml_p,
        "rules_score": rules_score,
        "rule_hits": hits,
        "extracted_links": links,
    }