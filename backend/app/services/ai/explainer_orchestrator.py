"""
VAJRA Forensic Platform - AI Explainer Orchestrator
SIH Problem Statement: SIH26106

Coordinates DLP sanitization and manages Groq Cloud LLM inference with deterministic heuristic fallback.
"""

import logging
from typing import Dict, Any
from app.core.config import settings
from app.services.dlp_shield import sanitize_text
from app.services.ai.groq_provider import (
    analyze_threat_with_groq_async,
    ThreatAnalysisReport,
)
from app.core.constants import get_static_briefing_template

logger = logging.getLogger("vajra.ai.orchestrator")


async def generate_threat_explanation(
    evidence: Dict[str, Any],
    raw_text: str,
    dlp_masking: bool = True,
) -> Dict[str, Any]:
    """Orchestrate executive threat briefing generation with DLP and Groq cloud inference."""
    dlp_active = False
    clean_text = raw_text or ""

    # 1. Apply DLP Shield if requested
    if dlp_masking and clean_text:
        clean_text, dlp_active = sanitize_text(clean_text)

    # Extract forensic telemetry
    verdict = evidence.get("verdict", "SAFE")
    score = evidence.get("score", 0)

    spf_status = evidence.get("spf_status") or "UNKNOWN"
    dkim_status = evidence.get("dkim_status") or "UNKNOWN"
    dmarc_status = evidence.get("dmarc_status") or "UNKNOWN"
    origin_ip = evidence.get("earliest_public_ip") or evidence.get("origin_ip") or "None"
    penalties_raw = evidence.get("penalties", [])

    subject = evidence.get("subject") or "Untitled"
    if dlp_masking and subject != "Untitled":
        subject, subj_dlp = sanitize_text(subject)
        if subj_dlp:
            dlp_active = True

    # Universal DLP Warning & Liability Alert System
    if not dlp_masking:
        dlp_security = {
            "status": "BYPASSED",
            "masking_active": False,
            "compliance_alert": (
                "CRITICAL RISK: DLP Masking was manually bypassed by operator. "
                "Raw enterprise text and potential PII have been exposed to cloud AI APIs. "
                "The platform assumes zero legal liability for unauthorized data egress or GDPR/DPDP non-compliance."
            ),
            "liability_disclaimed": True,
        }
    else:
        dlp_security = {
            "status": "ACTIVE",
            "masking_active": True,
            "compliance_alert": None,
            "liability_disclaimed": False,
        }

    # 2. Groq Cloud Inference (llama3-70b-8192 with strict JSON ThreatAnalysisReport)
    try:
        report: ThreatAnalysisReport = await analyze_threat_with_groq_async(clean_text, evidence=evidence)
        summary = f"[Engine: Groq Cloud Reasoning ({report.verdict})] {report.tldr} Action: {report.action}"
        return {
            "summary": summary,
            "engine_used": "groq",
            "ai_provider": "groq",
            "threat_report": report.model_dump(),
            "dlp_active": dlp_active,
            "dlp_security": dlp_security,
        }
    except Exception as groq_err:
        logger.warning(f"Groq engine unavailable or failed ({groq_err}); falling back to deterministic template.")

    # 3. Deterministic Forensic Static Template Fallback
    sender = evidence.get("sender") or "Unknown"
    raw_fallback = get_static_briefing_template(
        score=score,
        verdict=verdict,
        penalties=penalties_raw if isinstance(penalties_raw, list) else [],
        sender=sender,
        subject=subject,
    )
    fallback_summary = f"[Engine: Deterministic Heuristic Fallback] {raw_fallback.strip()}"

    return {
        "summary": fallback_summary,
        "engine_used": "fallback_template",
        "ai_provider": "heuristic",
        "threat_report": {
            "verdict": verdict,
            "tldr": raw_fallback.strip(),
            "red_flags": ["Heuristic assessment triggered based on observed email attributes."],
            "action": "Review sender legitimacy before opening attachments or following links."
        },
        "dlp_active": dlp_active,
        "dlp_security": dlp_security,
    }
