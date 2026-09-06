import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.config import settings
from app.core.database import get_db
from app.models.case import EmailCase
from app.models.user import User
from app.api.v1.endpoints.auth import get_current_user_optional
from app.schemas.analysis import (
    CaseResponseDTO,
    PaginatedCasesResponse,
    RawEmailRequest,
    HopDTO,
    AuthMatrixDTO,
    RiskBreakdownDTO,
    AttachmentMetaDTO,
)
from app.services.parser import (
    parse_rfc5322_bytes,
    parse_msg_bytes,
    parse_raw_text,
    ParsedEmailResult,
)
from app.services.hops import parse_hops_bottom_up
from app.services.auth_verifier import verify_authentication_matrix_sync
from app.services.geoip import lookup_ip_sync
from app.services.threat_intel import is_tor_exit_node, is_datacenter_asn
from app.services.risk_scorer import calculate_risk_score
from app.services.explainer import generate_analyst_summary
from app.services.report_generator import generate_html_report, generate_404_html

logger = logging.getLogger("vajra.api.analyze")
router = APIRouter()


async def _run_forensic_pipeline(
    raw_bytes: bytes,
    is_msg: bool = False,
    current_user: Optional[User] = None,
    db: Optional[AsyncSession] = None,
) -> CaseResponseDTO:
    """Core deterministic forensics orchestrator.

    Executes:
      1. Cryptographic SHA-256 evidence chain
      2. RFC 5322 or MSG structured parsing
      3. Reverse chronological hop traversal & entry IP isolation
      4. Synchronous cryptographic DKIM, DNS SPF & DMARC checks in worker thread
      5. Threat Intelligence (Tor Exit Node, Datacenter ASN)
      6. Deterministic scoring matrix (0-100)
      7. Local LLM reasoning with deterministic fallback
      8. Asynchronous persistence to PostgreSQL
    """
    # Step 1 & 2: Parse raw bytes in background thread
    if is_msg:
        parsed: ParsedEmailResult = await asyncio.to_thread(parse_msg_bytes, raw_bytes)
    else:
        parsed: ParsedEmailResult = await asyncio.to_thread(parse_rfc5322_bytes, raw_bytes)

    # Step 3: Reverse hop traversal (bottom-up) in worker thread
    hops_raw, earliest_public_ip = await asyncio.to_thread(
        parse_hops_bottom_up, parsed.received_headers
    )

    # Step 4: Authentication Verification (DKIM, SPF, DMARC) with 3.0s ceiling
    auth_matrix_raw = await asyncio.to_thread(
        verify_authentication_matrix_sync,
        raw_bytes,
        parsed.sender_domain,
        earliest_public_ip,
    )

    # Step 5: Threat intelligence on earliest public entry MTA IP
    is_tor = False
    is_dc = False
    if earliest_public_ip:
        is_tor = is_tor_exit_node(earliest_public_ip)
        geo = await asyncio.to_thread(lookup_ip_sync, earliest_public_ip)
        is_dc = is_datacenter_asn(geo.asn_org, geo.asn)

    # Step 6: Deterministic Scoring Matrix (0-100)
    risk_breakdown: RiskBreakdownDTO = calculate_risk_score(
        auth_matrix=auth_matrix_raw,
        is_tor_exit=is_tor,
        is_datacenter=is_dc,
        display_name_spoofed=parsed.display_name_spoofed,
        spoof_reason=parsed.spoof_reason,
    )

    # Prepare payload dictionary for LLM reasoning
    forensic_payload = {
        "subject": parsed.subject,
        "sender": parsed.sender,
        "sender_display_name": parsed.sender_display_name,
        "recipient": parsed.recipient,
        "earliest_public_ip": earliest_public_ip,
        "auth": auth_matrix_raw,
        "risk": risk_breakdown.model_dump(),
    }

    # Step 7: Local air-gapped LLM reasoning with immediate deterministic fallback
    llm_summary = await generate_analyst_summary(forensic_payload)

    # Convert hops to DTO
    hops_dto = [HopDTO(**h) for h in hops_raw]
    auth_dto = AuthMatrixDTO(**auth_matrix_raw)
    attachments_dto = [
        AttachmentMetaDTO(
            filename=att.filename,
            content_type=att.content_type,
            size_bytes=att.size_bytes,
            sha256=att.sha256,
        )
        for att in parsed.attachments
    ]

    # Step 8: Generate chronological readable Case ID (CAS-YYYYMMDD-XXXX)
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:4].upper()
    case_id = f"CAS-{date_str}-{suffix}"
    created_at = datetime.now(timezone.utc)

    case_response = CaseResponseDTO(
        case_id=case_id,
        sha256=parsed.sha256,
        subject=parsed.subject,
        sender=parsed.sender,
        sender_display_name=parsed.sender_display_name,
        recipient=parsed.recipient,
        date=parsed.date,
        message_id=parsed.message_id,
        return_path=parsed.return_path,
        earliest_public_ip=earliest_public_ip,
        auth=auth_dto,
        hops=hops_dto,
        attachments=attachments_dto,
        risk=risk_breakdown,
        llm_summary=llm_summary,
        created_at=created_at,
    )

    # Step 8: Persist to database asynchronously
    if db is not None:
        try:
            case_entity = EmailCase(
                case_id=case_id,
                sha256=parsed.sha256,
                sender=parsed.sender,
                recipient=parsed.recipient,
                subject=parsed.subject,
                risk_score=risk_breakdown.score,
                verdict=risk_breakdown.verdict,
                raw_intel=case_response.model_dump(mode="json"),
                user_id=current_user.id if current_user else None,
                created_at=created_at,
            )
            db.add(case_entity)
            await db.commit()
            logger.info(f"Committed forensic case {case_id} to database.")
        except Exception as e:
            logger.warning(f"Could not persist case {case_id} to database: {e}")
            await db.rollback()

    return case_response


@router.post(
    "/upload",
    response_model=CaseResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Ingest and analyze .eml or .msg file via multipart upload"
)
async def analyze_file_upload(
    file: UploadFile = File(..., description="Target email file (.eml or .msg format)"),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    filename = file.filename or "unknown.eml"
    ext = filename.lower().split(".")[-1] if "." in filename else ""

    if ext not in ("eml", "msg"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported email format. Upload must be an RFC 5322 (.eml) or Outlook (.msg) file."
        )

    # Read chunks enforcing strict 25MB ceiling
    chunk_size = 1024 * 1024  # 1MB
    total_bytes = 0
    buffer = bytearray()

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > settings.MAX_PAYLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Payload exceeds maximum allowed ceiling of {settings.MAX_PAYLOAD_BYTES // (1024*1024)}MB."
            )
        buffer.extend(chunk)

    raw_bytes = bytes(buffer)
    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty."
        )

    is_msg = (ext == "msg")
    return await _run_forensic_pipeline(
        raw_bytes=raw_bytes,
        is_msg=is_msg,
        current_user=current_user,
        db=db,
    )


@router.post(
    "/raw",
    response_model=CaseResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Analyze raw RFC 5322 header and body text strings via JSON payload"
)
async def analyze_raw_text(
    payload: RawEmailRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    raw_text = f"{payload.headers.strip()}\n\n{payload.body or ''}"
    raw_bytes = raw_text.encode("utf-8")

    if len(raw_bytes) > settings.MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Raw payload size {len(raw_bytes)} bytes exceeds {settings.MAX_PAYLOAD_BYTES // (1024*1024)}MB ceiling."
        )

    if not payload.headers.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Header block cannot be empty."
        )

    return await _run_forensic_pipeline(
        raw_bytes=raw_bytes,
        is_msg=False,
        current_user=current_user,
        db=db,
    )


@router.get(
    "/cases",
    response_model=PaginatedCasesResponse,
    summary="Retrieve paginated list of forensic investigation cases"
)
async def get_cases(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * limit

    try:
        # Total count query
        count_stmt = select(func.count()).select_from(EmailCase)
        count_res = await db.execute(count_stmt)
        total = count_res.scalar_one_or_none() or 0

        # Paginated items query
        stmt = (
            select(EmailCase)
            .order_by(desc(EmailCase.created_at))
            .offset(offset)
            .limit(limit)
        )
        res = await db.execute(stmt)
        cases = res.scalars().all()

        items = []
        for c in cases:
            try:
                # Reconstitute from stored raw_intel JSON
                items.append(CaseResponseDTO(**c.raw_intel))
            except Exception:
                pass

        return PaginatedCasesResponse(
            total=total,
            page=page,
            limit=limit,
            items=items,
        )
    except Exception as e:
        logger.warning(f"Database query failed in /cases: {e}")
        return PaginatedCasesResponse(total=0, page=page, limit=limit, items=[])


@router.get(
    "/cases/{case_id}",
    response_model=CaseResponseDTO,
    summary="Retrieve complete forensic dossier for a specific case ID"
)
async def get_case_by_id(
    case_id: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(EmailCase).where(EmailCase.case_id == case_id)
    try:
        res = await db.execute(stmt)
        case = res.scalar_one_or_none()
        if not case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Forensic case with ID '{case_id}' not found."
            )
        return CaseResponseDTO(**case.raw_intel)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching case {case_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve case from database."
        )


@router.get(
    "/cases/{case_id}/report",
    response_class=HTMLResponse,
    summary="Generate printable HTML/PDF forensic dossier for a case"
)
async def get_case_report(
    case_id: str,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(EmailCase).where(EmailCase.case_id == case_id)
    try:
        res = await db.execute(stmt)
        case = res.scalar_one_or_none()
        if not case:
            return HTMLResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content=generate_404_html(case_id),
            )
        return HTMLResponse(
            status_code=status.HTTP_200_OK,
            content=generate_html_report(case.raw_intel),
        )
    except Exception as e:
        logger.error(f"Error generating report for case {case_id}: {e}")
        return HTMLResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=generate_404_html(case_id),
        )
