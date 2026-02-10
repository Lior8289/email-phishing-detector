from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import uuid

from .api.router import api_router

app = FastAPI(title="Email Phishing Detector")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_stash: dict[str, dict] = {}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/stash")
def stash(request_body: dict):
    token = uuid.uuid4().hex[:12]
    _stash[token] = {
        "from_addr": request_body.get("from_addr", "")[:200],
        "subject": request_body.get("subject", "")[:500],
        "body": request_body.get("body", "")[:50000],
    }
    return {"token": token}

@app.get("/prefill/{token}")
def prefill(token: str):
    data = _stash.pop(token, None)
    if not data:
        return {"error": "expired or not found"}
    return data

app.include_router(api_router)