"""
VAJRA Forensic Platform - Historical Forensic Cases Routes
Provides paginated query access and single-case lookup against the in-memory case store.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from app.storage.memory_store import get_case, list_recent_cases, purge_cases
from app.schemas.analysis import CaseResponseDTO, PaginatedCasesResponse

logger = logging.getLogger("vajra.api.cases")

router = APIRouter()


@router.get(
    "/cases",
    response_model=PaginatedCasesResponse,
    summary="List recent forensic email cases",
    description="Retrieve paginated list of recent forensic email cases stored in RAM (most recent first).",
)
async def list_cases(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(25, ge=1, le=100, description="Items per page (max 100)"),
) -> PaginatedCasesResponse:
    all_cases = list_recent_cases()
    total = len(all_cases)
    start = (page - 1) * limit
    paged = all_cases[start : start + limit]

    return PaginatedCasesResponse(
        total=total,
        page=page,
        limit=limit,
        items=[CaseResponseDTO.model_validate(c) for c in paged],
    )


@router.get(
    "/cases/{case_id}",
    response_model=CaseResponseDTO,
    summary="Get single forensic case",
    description="Retrieve detailed forensic intelligence dossier for a specific case by its ID.",
)
async def get_case_by_id(case_id: str) -> CaseResponseDTO:
    clean_id = case_id.strip("\"' ")
    case_data = get_case(clean_id)
    if not case_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic case '{clean_id}' not found in active memory store.",
        )
    return CaseResponseDTO.model_validate(case_data)


@router.delete(
    "/cases",
    summary="Purge volatile RAM case store",
    description="Emergency ephemeral memory wipe. Zeroizes all active forensic cases in volatile RAM.",
)
@router.post(
    "/cases/purge",
    summary="Purge volatile RAM case store (POST alias)",
    description="Emergency ephemeral memory wipe alias. Zeroizes all active forensic cases in volatile RAM.",
)
async def purge_cases_store() -> dict:
    purged_count = purge_cases()
    logger.info("Volatile RAM case store purged (%d cases wiped)", purged_count)
    return {
        "status": "success",
        "message": "Volatile RAM case store purged successfully",
        "active_cases": 0,
    }
