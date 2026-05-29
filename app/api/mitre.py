from fastapi import APIRouter, Depends, Request, HTTPException

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
async def get_matrix(request: Request, _user: User = Depends(get_current_user)):
    """Return the full MITRE ATT&CK matrix with all mapped categories."""
    mapper = _get_mapper(request)
    return mapper.get_matrix()


@router.get("/lookup/{category}")
async def lookup_category(
    request: Request,
    category: str,
    _user: User = Depends(get_current_user),
):
    """Look up MITRE mapping for a single attack category."""
    mapper = _get_mapper(request)
    result = mapper.lookup(category)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"No MITRE mapping found for category: {category}",
        )
    return {"category": category, **result}
