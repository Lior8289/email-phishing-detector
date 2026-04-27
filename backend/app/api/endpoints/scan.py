from fastapi import APIRouter
from ...schemas.scan import ScanRequest, ScanResponse, RuleHit
from ...services.detector import detect

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    res = detect(
        req.from_addr,
        req.subject,
        req.body,
        headers=req.headers,
        attachments=req.attachments,
    )
    res["rule_hits"] = [RuleHit(**h) for h in res["rule_hits"]]
    return res
