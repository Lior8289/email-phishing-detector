from pydantic import BaseModel, Field
from typing import Optional


class RuleHit(BaseModel):
    id: str
    severity: int
    message: str


# ── Header info (parsed from raw email headers) ─────────

class HeaderInfo(BaseModel):
    spf: Optional[str] = None       # "pass" | "fail" | "softfail" | "neutral" | "none"
    dkim: Optional[str] = None      # "pass" | "fail" | "none"
    dmarc: Optional[str] = None     # "pass" | "fail" | "none"
    return_path: Optional[str] = None
    received_count: Optional[int] = None  # number of Received headers (hop count)


# ── Attachment metadata ──────────────────────────────────

class AttachmentInfo(BaseModel):
    filename: str
    mime_type: str = ""
    size: int = 0  # bytes


# ── Scan request / response ──────────────────────────────

class ScanRequest(BaseModel):
    from_addr: str = ""
    subject: str = ""
    body: str = Field(..., min_length=1)
    headers: Optional[HeaderInfo] = None
    attachments: Optional[list[AttachmentInfo]] = None


class EnrichmentResult(BaseModel):
    mx: Optional[dict] = None
    resolves: Optional[bool] = None
    soa: Optional[dict] = None


class ScanResponse(BaseModel):
    classification: str
    confidence: float
    ml_probability: Optional[float] = None

    rules_score: int
    rule_hits: list[RuleHit]
    extracted_links: list[str]

    enrichment: Optional[EnrichmentResult] = None
    sender_history: Optional[dict] = None     # {"times_flagged": N}
    blocklist_hit: bool = False


# ── Blocklist / Whitelist models ─────────────────────────

class BlocklistEntry(BaseModel):
    entry: str
    entry_type: str = "domain"     # "domain" | "email"
    reason: str = ""


class BlocklistResponse(BaseModel):
    id: int
    entry: str
    entry_type: str
    reason: str
    created_at: str


class WhitelistEntry(BaseModel):
    entry: str
    entry_type: str = "domain"


class WhitelistResponse(BaseModel):
    id: int
    entry: str
    entry_type: str
    created_at: str


# ── History models ───────────────────────────────────────

class HistoryItem(BaseModel):
    id: int
    from_addr: Optional[str]
    subject: Optional[str]
    classification: str
    confidence: float
    rules_score: int
    rule_hits: list[dict]
    scanned_at: str


class HistoryStats(BaseModel):
    total_scans: int
    phishing: int
    suspicious: int
    safe: int
    top_flagged_senders: list[dict]
