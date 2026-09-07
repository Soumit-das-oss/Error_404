"""
VAJRA Forensic Platform - Email Ingestion & Analysis Routes
Handles multipart file uploads (.eml / .msg) and raw RFC 5322 MIME text/json streams.
"""

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status, Query
from app.core.config import settings
from app.parsers.eml_parser import parse_eml_bytes
from app.parsers.msg_parser import parse_msg_bytes
from app.parsers.header_engine import parse_hops_and_origin, audit_authentication_headers
from app.analyzers.text_analyzer import analyze_text_patterns
from app.analyzers.url_analyzer import analyze_urls
from app.analyzers.qr_engine import extract_qr_codes, scan_qr_bytes, extract_qr_telemetry
from app.analyzers.pdf_engine import extract_pdf_telemetry
from app.services.risk_scorer import calculate_risk_score
from app.services.ai.explainer_orchestrator import generate_threat_explanation
from app.storage.memory_store import save_case
from app.schemas.analysis import CaseResponseDTO, RawEmailRequest, DlpOption

logger = logging.getLogger("vajra.api.analyze")

router = APIRouter()


async def execute_forensic_pipeline(parsed: Dict[str, Any], dlp_masking: bool = True) -> Dict[str, Any]:
    """Execute the full air-gapped forensic pipeline on parsed email data."""
    # 1. Reverse MTA hop traversal and origin pinpointing
    hops, earliest_public_ip = parse_hops_and_origin(parsed.get("received_headers", []))

    # 2. Cryptographic and DNS header authentication audit
    auth_result = audit_authentication_headers(
        auth_results=parsed.get("recorded_auth_results", []),
        received_spf=parsed.get("recorded_received_spf", []),
        dkim_signatures=parsed.get("recorded_dkim_signatures", []),
        raw_bytes=parsed.get("raw_bytes"),
    )

    # 3. Process attachments in-memory
    attachments = parsed.get("attachments", [])
    images_for_qr: List[bytes] = []
    pdf_links: List[str] = []
    pdf_deceptive_links: List[Dict[str, str]] = []
    pdf_text_snippets: List[str] = []
    attachment_meta: List[Dict[str, Any]] = []
    has_pdf_javascript = False
    has_pdf_launch = False
    has_pdf_attachment = False

    for att in attachments:
        fname = att.get("filename", "")
        ctype = att.get("content_type", "").lower()
        pbytes = att.get("payload_bytes", b"")
        sha256 = att.get("sha256", "")
        size = att.get("size_bytes", len(pbytes))

        attachment_meta.append({
            "filename": fname,
            "content_type": ctype,
            "size_bytes": size,
            "sha256": sha256,
        })

        if not pbytes:
            continue

        # In-memory PDF telemetry
        if ctype == "application/pdf" or fname.lower().endswith(".pdf"):
            has_pdf_attachment = True
            pdf_telem = extract_pdf_telemetry(pbytes)
            if pdf_telem.get("links"):
                pdf_links.extend(pdf_telem["links"])
            if pdf_telem.get("deceptive_links"):
                pdf_deceptive_links.extend(pdf_telem["deceptive_links"])
            if pdf_telem.get("images"):
                images_for_qr.extend(pdf_telem["images"])
            if pdf_telem.get("text"):
                pdf_text_snippets.append(pdf_telem["text"][:300])
            if pdf_telem.get("has_javascript"):
                has_pdf_javascript = True
            if pdf_telem.get("has_launch_action"):
                has_pdf_launch = True

        # Image telemetry
        elif ctype.startswith("image/") or any(fname.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".bmp", ".webp"]):
            images_for_qr.append(pbytes)

    # 4. QR Engine Quishing detection & evidence-based threat triage
    qr_telem = extract_qr_telemetry(images_for_qr)
    qr_urls = qr_telem["qr_urls"]
    is_suspicious_qr = qr_telem["is_suspicious_qr"]
    benign_qr_urls = qr_telem["benign_qr_urls"]
    quishing_detected = (len(qr_urls) > 0 and is_suspicious_qr)

    # 5. URL and deceptive hyperlink analysis
    all_aux_urls = list(set(pdf_links + qr_urls))
    url_result = analyze_urls(
        body_plain=parsed.get("body_plain"),
        body_html=parsed.get("body_html"),
        additional_urls=all_aux_urls,
    )

    all_deceptive_urls = list(url_result.get("deceptive_urls", []))
    for d in pdf_deceptive_links:
        if d not in all_deceptive_urls:
            all_deceptive_urls.append(d)

    # 6. Text social engineering & free webmail lure detection
    text_result = analyze_text_patterns(
        subject=parsed.get("subject", ""),
        body_plain=parsed.get("body_plain", ""),
        sender_display_name=parsed.get("sender_display_name"),
        sender_domain=parsed.get("sender_domain"),
        sender_address=parsed.get("sender_address"),
    )

    # 7. Deterministic risk scoring matrix
    risk_result = calculate_risk_score(
        auth_matrix=auth_result,
        deceptive_links=all_deceptive_urls,
        qr_urls=qr_urls,
        has_urgency=text_result["has_urgency"],
        urgency_matches=text_result["urgency_matches"],
        is_free_webmail_lure=text_result["is_free_webmail_lure"],
        lure_reason=text_result["lure_reason"],
        sender_domain=parsed.get("sender_domain"),
        has_financial_lure=text_result.get("has_financial_lure", False),
        financial_lure_matches=text_result.get("financial_lure_matches", []),
        quishing_detected=quishing_detected,
        is_suspicious_qr=is_suspicious_qr,
        benign_qr_urls=benign_qr_urls,
        has_pdf_javascript=has_pdf_javascript,
        has_pdf_launch=has_pdf_launch,
        pdf_deceptive_links=pdf_deceptive_links,
        is_authentic_pdf=has_pdf_attachment and not has_pdf_javascript and not has_pdf_launch and not pdf_deceptive_links,
    )

    # 8. AI Explainer with DLP and automatic 2-tier failover
    telemetry_for_ai = {
        "subject": parsed.get("subject"),
        "sender": parsed.get("sender"),
        "sender_domain": parsed.get("sender_domain"),
        "earliest_public_ip": earliest_public_ip,
        "score": risk_result["score"],
        "verdict": risk_result["verdict"],
        "penalties": risk_result["penalties"],
    }
    raw_text_for_ai = parsed.get("body_plain") or parsed.get("body_html") or parsed.get("subject") or ""

    ai_result = await generate_threat_explanation(
        evidence=telemetry_for_ai,
        raw_text=raw_text_for_ai,
        dlp_masking=dlp_masking,
    )

    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_id = uuid.uuid4().hex[:6].upper()
    case_id = f"CAS-{date_str}-{short_id}"
    created_at = datetime.now(timezone.utc)

    case_data = {
        "case_id": case_id,
        "sha256": parsed.get("sha256", ""),
        "subject": parsed.get("subject"),
        "sender": parsed.get("sender"),
        "sender_display_name": parsed.get("sender_display_name"),
        "sender_address": parsed.get("sender_address"),
        "sender_domain": parsed.get("sender_domain"),
        "recipient": parsed.get("recipient"),
        "date": parsed.get("date"),
        "message_id": parsed.get("message_id"),
        "return_path": parsed.get("return_path"),
        "earliest_public_ip": earliest_public_ip,
        "auth": auth_result,
        "recorded_authentication": {
            "authentication_results": parsed.get("recorded_auth_results", []),
            "received_spf": parsed.get("recorded_received_spf", []),
            "dkim_signatures": parsed.get("recorded_dkim_signatures", []),
        },
        "independent_verification": auth_result,
        "artifacts": {
            "plain_text_snippet": (parsed.get("body_plain", "")[:300] if parsed.get("body_plain") else None),
            "html_links_count": len(url_result.get("extracted_urls", [])),
            "extracted_urls": url_result.get("extracted_urls", []),
            "deceptive_urls": all_deceptive_urls,
            "pdf_extracted_links": pdf_links,
            "pdf_extracted_text_snippets": pdf_text_snippets,
            "qr_code_urls": qr_urls,
            "quishing_detected": quishing_detected,
            "ocr_extracted_text": [],
        },
        "engine_warnings": [],
        "hops": hops,
        "attachments": attachment_meta,
        "risk": {
            "score": risk_result["score"],
            "verdict": risk_result["verdict"],
            "itemized_penalties": risk_result["penalties"],
            "engine_warnings": [],
        },
        "verdict": risk_result["verdict"],
        "quishing_detected": quishing_detected,
        "llm_summary": ai_result["summary"],
        "dlp_security": ai_result.get("dlp_security", {
            "status": "ACTIVE" if dlp_masking else "BYPASSED",
            "masking_active": dlp_masking,
            "compliance_alert": None if dlp_masking else (
                "CRITICAL RISK: DLP Masking was manually bypassed by operator. "
                "Raw enterprise text and potential PII have been exposed to cloud AI APIs. "
                "The platform assumes zero legal liability for unauthorized data egress or GDPR/DPDP non-compliance."
            ),
            "liability_disclaimed": not dlp_masking,
        }),
        "dlp_active": ai_result.get("dlp_active", False),
        "dlp_masking": dlp_masking,
        "created_at": created_at,
    }

    return case_data


@router.post(
    "/upload",
    response_model=CaseResponseDTO,
    summary="Analyze uploaded email file (.eml / .msg)",
    description="Upload an RFC 5322 .eml or Outlook .msg file for comprehensive forensic examination.",
)
@router.post(
    "/analyze/upload",
    response_model=CaseResponseDTO,
    include_in_schema=False,
)
async def analyze_email_upload(
    request: Request,
    file: UploadFile = File(..., description="Email file (.eml or .msg)"),
    dlp_masking: DlpOption = Query(..., description="Enable local in-memory PII masking"),
) -> CaseResponseDTO:
    is_dlp_active = (dlp_masking == DlpOption.TRUE or str(dlp_masking).lower() == "true")
    query_dlp = request.query_params.get("dlp_masking")
    if query_dlp is not None:
        is_dlp_active = query_dlp.lower() not in ("false", "0", "no")
    else:
        # Check multipart form data if not explicitly set in query
        try:
            form = await request.form()
            if "dlp_masking" in form:
                is_dlp_active = str(form["dlp_masking"]).lower() not in ("false", "0", "no")
        except Exception:
            pass

    content = await file.read()
    if not content or len(content) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file payload is empty or invalid (minimum 10 bytes required).",
        )

    if len(content) > settings.MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_PAYLOAD_BYTES // (1024 * 1024)} MB.",
        )

    filename = (file.filename or "").lower()
    if filename.endswith(".msg"):
        try:
            parsed = parse_msg_bytes(content)
        except Exception as e:
            logger.error(f"Outlook MSG parse failed: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Failed to parse Outlook .msg file structure: {str(e)}",
            )
    else:
        parsed = parse_eml_bytes(content)

    case_data = await execute_forensic_pipeline(parsed, dlp_masking=is_dlp_active)
    saved = save_case(case_data)
    return CaseResponseDTO.model_validate(saved)


@router.post(
    "/raw",
    response_model=CaseResponseDTO,
    summary="Analyze raw RFC 5322 email string, multipart form with attachments, or text stream",
    description="Analyze raw RFC 5322 email text submitted via JSON payload, multipart form with file attachments, or direct plain text stream.",
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": RawEmailRequest.model_json_schema()
                },
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "raw_email": {
                                "type": "string",
                                "description": "Full RFC 5322 email text (headers + body)",
                                "example": "From: security@paypal-alerts.com\nTo: victim@example.com\nSubject: Account Suspended\n\nDear user, verify your account within 24 hours."
                            },
                            "attachments": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "format": "binary"
                                },
                                "description": "Mobile file attachments (PDF documents or QR code images)"
                            }
                        },
                        "required": ["raw_email"]
                    }
                },
                "text/plain": {
                    "schema": {
                        "type": "string",
                        "example": "From: security@paypal-alerts.com\nTo: victim@example.com\nSubject: Account Suspended\n\nDear user, verify your account within 24 hours."
                    }
                }
            },
            "required": True,
            "description": "Full RFC 5322 email text submitted as JSON, multipart form with attachments, or raw plain text stream."
        }
    }
)
@router.post(
    "/analyze/raw",
    response_model=CaseResponseDTO,
    include_in_schema=False,
)
async def analyze_raw_email(
    request: Request,
    dlp_masking: DlpOption = Query(..., description="Enable local in-memory PII masking"),
) -> CaseResponseDTO:
    content_type = request.headers.get("content-type", "").lower()

    is_dlp_active = (dlp_masking == DlpOption.TRUE or str(dlp_masking).lower() == "true")
    query_dlp = request.query_params.get("dlp_masking")
    if query_dlp is not None:
        is_dlp_active = query_dlp.lower() not in ("false", "0", "no")

    raw_bytes: bytes = b""
    extra_attachments: List[Dict[str, Any]] = []

    # 1. Handle Form Data (Multipart Mobile Flow or urlencoded browser form)
    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        raw_email_val = form.get("raw_email") or form.get("email") or ""
        if hasattr(raw_email_val, "read"):
            raw_bytes = await raw_email_val.read()
        else:
            raw_email_str = str(raw_email_val).strip()
            raw_bytes = raw_email_str.encode("utf-8", errors="ignore")

        if query_dlp is None and "dlp_masking" in form:
            is_dlp_active = str(form["dlp_masking"]).lower() not in ("false", "0", "no")

        # Ingest mobile attachments in-memory dynamically (zero disk writes)
        form_entries = form.multi_items() if hasattr(form, "multi_items") else form.items()
        for key, item in form_entries:
            if key in ("raw_email", "email", "dlp_masking"):
                continue
            if hasattr(item, "read") and hasattr(item, "filename"):
                f_bytes = await item.read()
                if not f_bytes:
                    continue
                if len(f_bytes) > settings.MAX_PAYLOAD_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Attachment exceeds maximum allowed size of {settings.MAX_PAYLOAD_BYTES // (1024 * 1024)} MB.",
                    )
                fname = getattr(item, "filename", "") or "mobile_attachment"
                f_ctype = (getattr(item, "content_type", "") or "application/octet-stream").lower()
                extra_attachments.append({
                    "filename": fname,
                    "content_type": f_ctype,
                    "size_bytes": len(f_bytes),
                    "payload_bytes": f_bytes,
                    "sha256": hashlib.sha256(f_bytes).hexdigest(),
                })
    else:
        # 2. Handle JSON and Plain Text streams
        body_bytes = await request.body()
        if len(body_bytes) > settings.MAX_PAYLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Payload exceeds maximum allowed size of {settings.MAX_PAYLOAD_BYTES // (1024 * 1024)} MB.",
            )

        is_json = "application/json" in content_type or body_bytes.strip().startswith(b"{")
        if is_json:
            try:
                body_json = json.loads(body_bytes.decode("utf-8", errors="ignore"))
                if isinstance(body_json, dict):
                    if "raw_email" in body_json:
                        email_str = str(body_json["raw_email"] or "")
                        raw_bytes = email_str.encode("utf-8", errors="ignore")
                    elif "headers" in body_json:
                        headers = str(body_json.get("headers") or "").strip()
                        body = str(body_json.get("body") or "").strip()
                        raw_bytes = f"{headers}\n\n{body}".strip().encode("utf-8", errors="ignore")
                    else:
                        raw_bytes = body_bytes
                elif isinstance(body_json, str):
                    raw_bytes = body_json.encode("utf-8", errors="ignore")
                else:
                    raw_bytes = body_bytes
            except Exception:
                text_decoded = body_bytes.decode("utf-8", errors="ignore").strip()
                match = re.search(r'"raw_email"\s*:\s*"(.*)"\s*\}?$', text_decoded, re.DOTALL)
                if match:
                    raw_bytes = match.group(1).encode("utf-8", errors="ignore")
                else:
                    raw_bytes = body_bytes
        else:
            # text/plain or raw data stream: read raw body bytes directly
            raw_bytes = body_bytes

    if len(raw_bytes.strip()) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Raw email payload must be at least 10 characters.",
        )

    parsed = parse_eml_bytes(raw_bytes)
    if extra_attachments:
        parsed.setdefault("attachments", []).extend(extra_attachments)

    case_data = await execute_forensic_pipeline(parsed, dlp_masking=is_dlp_active)
    saved = save_case(case_data)
    return CaseResponseDTO.model_validate(saved)
