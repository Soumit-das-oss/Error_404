"""
VAJRA Forensic Platform - AI Explainer Orchestrator & Auto-Failover Controller
SIH Problem Statement: SIH26106

Coordinates DLP sanitization and manages automatic 3-tier failover:
  Tier 1: Cloud LLM (Groq API, 4.0s timeout)
  Tier 2: Local Offline LLM (Ollama instance, 15-25s timeout)
  Tier 3: Deterministic Forensic Static Heuristic Briefing (Offline Guarantee)
"""

import logging
from typing import Dict, Any
from app.core.config import settings
from app.services.dlp_shield import sanitize_text
from app.services.ai.groq_provider import generate_groq_briefing
from app.services.ai.ollama_provider import (
    generate_ollama_briefing,
    get_last_used_model,
    REFUSAL_TRIGGERS,
    VAJRA_SOC_SYSTEM_PROMPT,
)
from app.core.constants import get_static_briefing_template

logger = logging.getLogger("vajra.ai.orchestrator")


async def generate_threat_explanation(
    evidence: Dict[str, Any],
    raw_text: str,
    dlp_masking: bool = True,
) -> Dict[str, Any]:
    """Orchestrate 2-sentence executive threat briefing generation with DLP and 3-tier failover.

    Returns:
      {"summary": str, "engine_used": "groq" | "ollama" | "fallback_template", "ai_provider": str, "dlp_active": bool}
    """
    dlp_active = False
    clean_text = raw_text or ""

    # 1. Apply DLP Shield if requested
    if dlp_masking and clean_text:
        clean_text, dlp_active = sanitize_text(clean_text)

    # Extract forensic telemetry for the defensive SOC auditor prompt
    verdict = evidence.get("verdict", "SAFE")
    score = evidence.get("score", 0)

    # Authentication claim audit
    spf_status = evidence.get("spf_status")
    dkim_status = evidence.get("dkim_status")
    dmarc_status = evidence.get("dmarc_status")

    auth = evidence.get("auth")
    if isinstance(auth, dict):
        if not spf_status:
            spf_val = auth.get("spf", {})
            spf_status = (spf_val.get("status") if isinstance(spf_val, dict) else str(spf_val))
        if not dkim_status:
            dkim_val = auth.get("dkim", {})
            dkim_status = (dkim_val.get("status") if isinstance(dkim_val, dict) else str(dkim_val))
        if not dmarc_status:
            dmarc_val = auth.get("dmarc", {})
            dmarc_status = (dmarc_val.get("status") if isinstance(dmarc_val, dict) else str(dmarc_val))

    spf_status = spf_status or "UNKNOWN"
    dkim_status = dkim_status or "UNKNOWN"
    dmarc_status = dmarc_status or "UNKNOWN"

    origin_ip = evidence.get("earliest_public_ip") or evidence.get("origin_ip") or "None"

    asn = evidence.get("asn")
    if not asn:
        hops = evidence.get("hops", [])
        if isinstance(hops, list) and hops:
            first_hop = hops[0] if isinstance(hops[0], dict) else {}
            asn = first_hop.get("asn_org") or (f"AS{first_hop.get('asn')}" if first_hop.get("asn") else None)
    asn = asn or "Unknown"

    penalties_raw = evidence.get("penalties", [])
    if isinstance(penalties_raw, list) and penalties_raw:
        penalty_items = []
        for p in penalties_raw:
            if isinstance(p, dict):
                rule = p.get("rule", "Anomaly")
                pts = p.get("penalty")
                penalty_items.append(f"{rule} (+{pts})" if pts is not None else rule)
            else:
                penalty_items.append(str(p))
        penalties_str = ", ".join(penalty_items) if penalty_items else "None"
    elif isinstance(penalties_raw, str) and penalties_raw.strip():
        penalties_str = penalties_raw.strip()
    else:
        penalties_str = "None"

    subject = evidence.get("subject") or "Untitled"
    if dlp_masking and subject != "Untitled":
        subject, subj_dlp = sanitize_text(subject)
        if subj_dlp:
            dlp_active = True

    # Passive evidentiary SOC evaluation template (objective, refusal-resistant)
    prompt = (
        "Forensic Case Telemetry:\n"
        f"- Final Verdict: {verdict} (Score: {score}/100)\n"
        f"- Authentication Claim Audit: SPF={spf_status}, DKIM={dkim_status}, DMARC={dmarc_status}\n"
        f"- Observed Infrastructure: IP {origin_ip} (ASN: {asn})\n"
        f"- Triggered Indicators: {penalties_str}\n"
        f"- Subject: {subject}\n\n"
        "Explain why the message received this verdict based strictly on the telemetry above in exactly 2 concise, factual sentences."
    )

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

    # 2. Tier 1: Groq Cloud Provider (4.0s timeout)
    try:
        raw_summary = await generate_groq_briefing(prompt, system_prompt=VAJRA_SOC_SYSTEM_PROMPT)
        if raw_summary:
            raw_summary = raw_summary.strip()
            norm_groq = raw_summary.lower()
            if len(raw_summary) < 25 or any(t in norm_groq for t in REFUSAL_TRIGGERS):
                logger.warning("Groq safety refusal detected; failing over to Tier 2 (Ollama).")
                raw_summary = None

        if not raw_summary:
            raise ValueError("Groq returned empty or refused response.")

        logger.info("Successfully generated threat briefing via Tier 1 Groq cloud engine.")
        summary = f"[Engine: Groq Cloud Reasoning] {raw_summary}"
        return {
            "summary": summary,
            "engine_used": "groq",
            "ai_provider": "groq",
            "dlp_active": dlp_active,
            "dlp_security": dlp_security,
        }
    except Exception as groq_err:
        logger.warning("Tier 1 (Groq Cloud) unavailable or offline. Engaging Tier 2 (Local Air-Gapped Ollama)...")
        logger.debug(f"Tier 1 (Groq) error detail: {groq_err}")

    # 3. Tier 2: Ollama Local Air-Gapped Provider (15-25s timeout)
    try:
        raw_summary = await generate_ollama_briefing(prompt, system_prompt=VAJRA_SOC_SYSTEM_PROMPT)
        if raw_summary:
            raw_summary = raw_summary.strip()
            normalized_summary = raw_summary.lower()
            if len(raw_summary) < 25 or any(trigger in normalized_summary for trigger in REFUSAL_TRIGGERS):
                logger.warning("Ollama safety refusal detected. Discarding output and falling back to Tier 3 Heuristics.")
                raw_summary = None

        if not raw_summary:
            logger.warning("Tier 2 (Ollama) output invalid or refused; falling back to Tier 3 (Deterministic Template).")
        else:
            logger.info("Successfully generated threat briefing via Tier 2 Ollama local engine.")
            used_model = get_last_used_model() or settings.OLLAMA_MODEL
            summary = f"[Engine: Local Air-Gapped Ollama ({used_model})] {raw_summary}"
            return {
                "summary": summary,
                "engine_used": "ollama",
                "ai_provider": "ollama",
                "dlp_active": dlp_active,
                "dlp_security": dlp_security,
            }
    except Exception as ollama_err:
        logger.warning(f"Tier 2 (Ollama) unavailable or failed ({ollama_err}); falling back to Tier 3 (Deterministic Template).")

    # 4. Tier 3: Deterministic Forensic Static Template (Guaranteed Offline / Air-Gapped)
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
        "dlp_active": dlp_active,
        "dlp_security": dlp_security,
    }
