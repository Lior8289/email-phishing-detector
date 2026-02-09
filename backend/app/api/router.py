from fastapi import APIRouter
from .endpoints.scan import router as scan_router

api_router = APIRouter()
api_router.include_router(scan_router)

