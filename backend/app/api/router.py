from fastapi import APIRouter
from .endpoints.scan import router as scan_router
from .endpoints.blocklist import router as blocklist_router
from .endpoints.history import router as history_router

api_router = APIRouter()
api_router.include_router(scan_router)
api_router.include_router(blocklist_router)
api_router.include_router(history_router)
