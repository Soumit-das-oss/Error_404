"""
VAJRA Forensic Platform - PDF Report Export Route
Streams certified, cryptographic digital forensic PDF dossiers directly from memory.
"""

import logging
from fastapi import APIRouter, HTTPException, Response, status
from app.storage.memory_store import get_case
from app.services.report_generator import generate_case_pdf

logger = logging.getLogger("vajra.api.reports")

router = APIRouter()


@router.get(
    "/cases/{case_id}/pdf",
    summary="Download certified forensic PDF report",
    description="Stream an executive-grade Platypus PDF forensic dossier for a case directly from memory.",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Streamed binary PDF report.",
        },
        404: {"description": "Case not found in memory store."},
    },
)
async def download_case_pdf(case_id: str):
    case_data = get_case(case_id)
    if not case_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic case '{case_id}' not found in active memory store.",
        )

    try:
        pdf_bytes = generate_case_pdf(case_data)
    except Exception as e:
        logger.error(f"Failed to generate PDF for case {case_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate forensic PDF dossier: {str(e)}",
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="VAJRA_CASE_{case_id}.pdf"',
            "Content-Type": "application/pdf",
        },
    )
