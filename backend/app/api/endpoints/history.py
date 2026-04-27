from fastapi import APIRouter
from ...schemas.scan import HistoryItem, HistoryStats
from ...services.storage import get_history, get_history_stats

router = APIRouter(tags=["history"])


@router.get("/history", response_model=list[HistoryItem])
def list_history(limit: int = 50):
    return get_history(limit=min(limit, 200))


@router.get("/history/stats", response_model=HistoryStats)
def history_stats():
    return get_history_stats()
