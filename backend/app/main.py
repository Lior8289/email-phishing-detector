from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import uuid

from .api.router import api_router
from .services.storage import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Email Phishing Detector", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_stash: dict[str, dict] = {}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/stash")
def stash(request_body: dict):
    # Keep stash bounded to prevent memory leak
    if len(_stash) > 500:
        oldest = list(_stash.keys())[:250]
        for k in oldest:
            _stash.pop(k, None)

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
