import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.storage import init_db

# Ensure DB tables exist before tests run
init_db()

client = TestClient(app)


# ── Health ───────────────────────────────────────────────

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ── Basic scan ───────────────────────────────────────────

def test_scan_basic():
    r = client.post("/scan", json={
        "from_addr": "test@example.com",
        "subject": "Hello",
        "body": "Just a normal email body."
    })
    assert r.status_code == 200
    data = r.json()
    assert data["classification"] in {"Safe", "Suspicious", "Phishing"}
    assert 0.0 <= data["confidence"] <= 1.0
    assert isinstance(data["rule_hits"], list)
    assert isinstance(data["extracted_links"], list)


def test_scan_requires_body():
    r = client.post("/scan", json={
        "from_addr": "test@example.com",
        "subject": "Hello",
        "body": ""
    })
    assert r.status_code == 422  # validation error — body min_length=1


# ── Phishing detection ──────────────────────────────────

def test_scan_detects_phishing_signals():
    r = client.post("/scan", json={
        "from_addr": "support@paypaI.com",
        "subject": "URGENT: verify your account",
        "body": "Click http://bit.ly/xyz now to verify your account or it will be suspended."
    })
    assert r.status_code == 200
    data = r.json()
    assert data["classification"] in {"Suspicious", "Phishing"}
    assert len(data["rule_hits"]) > 0
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert any("urgent" in rid for rid in rule_ids)


def test_scan_detects_typosquatting():
    r = client.post("/scan", json={
        "from_addr": "alerts@amaz0n-orders.com",
        "subject": "Your order shipped",
        "body": "Visit http://amaz0n-orders.com/track to track your package."
    })
    data = r.json()
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert "sender_typosquatting" in rule_ids or "typosquatting" in rule_ids


def test_scan_detects_scam_patterns():
    r = client.post("/scan", json={
        "from_addr": "prince@royalfund.com",
        "subject": "Inheritance funds",
        "body": "Dear Friend, I am a prince with $24 million dollars in a foreign security vault. "
                "Send processing fee of $500 via Western Union. 100% risk free."
    })
    data = r.json()
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert "scam_phrases" in rule_ids


# ── Header authentication rules ─────────────────────────

def test_scan_with_header_spf_fail():
    r = client.post("/scan", json={
        "from_addr": "info@company.com",
        "subject": "Important update",
        "body": "Please review the attached document.",
        "headers": {
            "spf": "fail",
            "dkim": "pass",
            "dmarc": "pass"
        }
    })
    data = r.json()
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert "spf_fail" in rule_ids


def test_scan_with_header_dkim_fail():
    r = client.post("/scan", json={
        "from_addr": "info@company.com",
        "subject": "Important update",
        "body": "Please review the attached document.",
        "headers": {
            "spf": "pass",
            "dkim": "fail",
            "dmarc": "pass"
        }
    })
    data = r.json()
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert "dkim_fail" in rule_ids


def test_scan_with_return_path_mismatch():
    r = client.post("/scan", json={
        "from_addr": "info@legit-company.com",
        "subject": "Invoice",
        "body": "Please pay this invoice.",
        "headers": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "return_path": "bounces@evil-spammer.com"
        }
    })
    data = r.json()
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert "return_path_mismatch" in rule_ids


# ── Attachment rules ─────────────────────────────────────

def test_scan_flags_executable_attachment():
    r = client.post("/scan", json={
        "from_addr": "sender@example.com",
        "subject": "Check this file",
        "body": "Please see attached.",
        "attachments": [
            {"filename": "invoice.exe", "mime_type": "application/octet-stream", "size": 45000}
        ]
    })
    data = r.json()
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert "executable_attachment" in rule_ids


def test_scan_flags_double_extension():
    r = client.post("/scan", json={
        "from_addr": "sender@example.com",
        "subject": "Document",
        "body": "Here is the document you requested.",
        "attachments": [
            {"filename": "report.pdf.exe", "mime_type": "application/octet-stream", "size": 12000}
        ]
    })
    data = r.json()
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert "double_extension" in rule_ids


def test_scan_flags_password_protected_archive():
    r = client.post("/scan", json={
        "from_addr": "sender@example.com",
        "subject": "Files",
        "body": "Attached are the files. The password is 12345.",
        "attachments": [
            {"filename": "data.zip", "mime_type": "application/zip", "size": 80000}
        ]
    })
    data = r.json()
    rule_ids = [h["id"] for h in data["rule_hits"]]
    assert "password_protected_archive" in rule_ids


# ── Enrichment in response ───────────────────────────────

def test_scan_includes_enrichment():
    r = client.post("/scan", json={
        "from_addr": "info@google.com",
        "subject": "Test",
        "body": "Just testing enrichment."
    })
    data = r.json()
    assert "enrichment" in data
    # enrichment should have mx info
    if data["enrichment"]:
        assert "mx" in data["enrichment"]


# ── Blocklist CRUD ───────────────────────────────────────

def test_blocklist_crud():
    # Add
    r = client.post("/blocklist", json={"entry": "test-evil.com", "entry_type": "domain", "reason": "test"})
    assert r.status_code == 201

    # List
    r = client.get("/blocklist")
    assert r.status_code == 200
    items = r.json()
    assert any(i["entry"] == "test-evil.com" for i in items)

    # Get the ID
    entry_id = next(i["id"] for i in items if i["entry"] == "test-evil.com")

    # Delete
    r = client.delete(f"/blocklist/{entry_id}")
    assert r.status_code == 200

    # Verify deleted
    r = client.get("/blocklist")
    assert not any(i["entry"] == "test-evil.com" for i in r.json())


# ── History ──────────────────────────────────────────────

def test_history_endpoint():
    # Trigger a scan first to populate history
    client.post("/scan", json={
        "from_addr": "history-test@example.com",
        "subject": "History test",
        "body": "Testing history recording."
    })

    r = client.get("/history?limit=5")
    assert r.status_code == 200
    items = r.json()
    assert isinstance(items, list)
    assert len(items) > 0


def test_history_stats():
    r = client.get("/history/stats")
    assert r.status_code == 200
    data = r.json()
    assert "total_scans" in data
    assert "phishing" in data
    assert "suspicious" in data
    assert "safe" in data


# ── Safe email stays safe ────────────────────────────────

def test_safe_email():
    r = client.post("/scan", json={
        "from_addr": "newsletter@medium.com",
        "subject": "Your weekly reading recommendations",
        "body": "Hi there, here are this week's top stories curated just for you. Happy reading!"
    })
    data = r.json()
    assert data["classification"] == "Safe"


# ── Stash / prefill ─────────────────────────────────────

def test_stash_and_prefill():
    r = client.post("/stash", json={
        "from_addr": "test@example.com",
        "subject": "Test stash",
        "body": "Stash body"
    })
    assert r.status_code == 200
    token = r.json()["token"]

    r = client.get(f"/prefill/{token}")
    assert r.status_code == 200
    data = r.json()
    assert data["from_addr"] == "test@example.com"

    # Token should be consumed
    r = client.get(f"/prefill/{token}")
    data = r.json()
    assert "error" in data
