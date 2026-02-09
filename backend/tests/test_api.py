from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True

def test_scan():
    r = client.post("/scan", json={
        "from_addr": "support@paypaI.com",
        "subject": "URGENT verify",
        "body": "Click http://bit.ly/xyz now"
    })
    assert r.status_code == 200
    data = r.json()
    assert data["classification"] in {"Safe","Suspicious","Phishing"}
    assert 0.0 <= data["confidence"] <= 1.0
