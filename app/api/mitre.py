from fastapi import APIRouter, Depends, Request, Response, HTTPException

from app.auth.dependencies import get_current_user
from app.core.mitre_mapper import MitreMapper
from app.db.models import User

router = APIRouter(prefix="/mitre", tags=["mitre"])


def _get_mapper(request: Request) -> MitreMapper:
    mapper = getattr(request.app.state, "mitre_mapper", None)
    if mapper is None:
        raise HTTPException(status_code=503, detail="MITRE mapper not initialized")
    return mapper


@router.get("/matrix")
async def get_matrix(request: Request, response: Response, _user: User = Depends(get_current_user)):
    """Return the full MITRE ATT&CK matrix with all mapped categories."""
    # Carries runtime `unmapped_attack_types`; keep it uncached so a freshly
    # seen leaf shows up without a stale-cache lag.
    response.headers["Cache-Control"] = "no-store"
    mapper = _get_mapper(request)
    return mapper.get_matrix()


@router.get("/lookup/{category}")
async def lookup_category(
    request: Request,
    response: Response,
    category: str,
    _user: User = Depends(get_current_user),
):
    """Look up MITRE mapping for a single attack category."""
    response.headers["Cache-Control"] = "no-store"
    mapper = _get_mapper(request)
    result = mapper.lookup(category)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"No MITRE mapping found for category: {category}",
        )
    return {"category": category, **result}
