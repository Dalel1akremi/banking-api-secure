from fastapi import APIRouter

router = APIRouter()

@router.get("/locations")
async def get_locations():
    # Deprecated: Frontend uses Overpass API directly now.
    return {"status": "success", "locations": []}
