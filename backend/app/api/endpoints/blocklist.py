from fastapi import APIRouter, HTTPException
from ...schemas.scan import BlocklistEntry, BlocklistResponse, WhitelistEntry, WhitelistResponse
from ...services.storage import (
    add_blocklist, remove_blocklist, get_blocklist,
    add_whitelist, remove_whitelist, get_whitelist,
)

router = APIRouter(tags=["blocklist"])


# ── Blocklist CRUD ───────────────────────────────────────

@router.get("/blocklist", response_model=list[BlocklistResponse])
def list_blocklist():
    return get_blocklist()


@router.post("/blocklist", status_code=201)
def create_blocklist_entry(entry: BlocklistEntry):
    add_blocklist(entry.entry, entry.entry_type, entry.reason)
    return {"status": "added", "entry": entry.entry}


@router.delete("/blocklist/{entry_id}")
def delete_blocklist_entry(entry_id: int):
    remove_blocklist(entry_id)
    return {"status": "removed"}


# ── Whitelist CRUD ───────────────────────────────────────

@router.get("/whitelist", response_model=list[WhitelistResponse])
def list_whitelist():
    return get_whitelist()


@router.post("/whitelist", status_code=201)
def create_whitelist_entry(entry: WhitelistEntry):
    add_whitelist(entry.entry, entry.entry_type)
    return {"status": "added", "entry": entry.entry}


@router.delete("/whitelist/{entry_id}")
def delete_whitelist_entry(entry_id: int):
    remove_whitelist(entry_id)
    return {"status": "removed"}
