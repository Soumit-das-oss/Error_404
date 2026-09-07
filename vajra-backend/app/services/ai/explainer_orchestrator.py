"""
VAJRA Forensic Platform - AI Explainer Orchestrator & Auto-Failover Controller
Coordinates DLP sanitization and manages automatic failover from Groq -> Ollama -> Static Template.
"""

import logging
from typing import Dict, Any
from app.services.dlp_shield import sanitize_text
from app.services.ai.groq_provider import generate_groq_briefing
from app.services.ai.ollama_provider import generate_ollama_briefing
from app.core.constants import get_static_briefing_template

logger = logging.getLogger("vajra.ai.orchestrator")


async def generate_threat_explanation(
    evidence: Dict[str, Any],
    raw_text: str,
    dlp_masking: bool = True,
) -> Dict[str, Any]:
    """Orchestrate 3-sentence executive threat briefing generation with DLP and 2-tier failover.

    Returns:
      {"summary": str, "engine_used": "groq" | "ollama" | "fallback_template", "dlp_active": bool}
    """
    dlp_active = False
    clean_text = raw_text or ""

    # 1. Apply DLP Shield if requested
    if dlp_masking and clean_text:
        clean_text, dlp_active = sanitize_text(clean_text)

    # Extract key telemetry for the prompt
    subject = evidence.get("subject") or "Untitled"
    sender = evidence.get("sender") or "Unknown"
    sender_domain = evidence.get("sender_domain") or "Unknown"
    candidate_ip = evidence.get("earliest_public_ip") or "None"
    score = evidence.get("score", 0)
    verdict = evidence.get("verdict", "SAFE")
    penalties = evidence.get("penalties", [])

    penalty_rules = [p.get("rule", str(p)) for p in penalties] if isinstance(penalties, list) else []
    triggers_str = ", ".join(penalty_rules) if penalty_rules else "Zero penalties triggered"

    # Truncate body if very long to fit fast reasoning window
    body_snippet = clean_text[:1200] if len(clean_text) > 1200 else clean_text

    # Dynamic prompt construction based on verdict and risk score
    if verdict == "SAFE" or score < 20:
        analyst_prompt = (
            f"You are an Elite SOC Analyst. The email has PASSED cryptographic authentication (SPF/DKIM/DMARC) and forensic audit with a SAFE risk score of {score}/100.\n"
            "Write a concise 2-3 sentence executive clearance notice:\n"
            "1. Confirm the communication is legitimate, authentic corporate or marketing traffic from the verified sender domain.\n"
            "2. Note that telemetry verified SPF/DKIM integrity and zero malicious payloads or deceptive links were found.\n"
            "3. Action: Permit inbox delivery with standard telemetry logging; no blocking, quarantine, or containment is required.\n"
            "DO NOT declare this message as phishing, malware, or an attack."
        )
    else:
        analyst_prompt = (
            f"You are an Elite SOC Analyst. A potential email threat was detected with a risk score of {score}/100 ({verdict}).\n"
            "Write a 3-sentence threat briefing:\n"
            "1. Specific attack vector and attacker intent.\n"
            "2. Telemetry proof (headers, hops, links, or lure keywords).\n"
            "3. Immediate SOC containment action (quarantine, block sender/IP)."
        )

    prompt = (
        f"{analyst_prompt}\n\n"
        f"--- TELEMETRY ---\n"
        f"Subject: {subject}\n"
        f"Sender: {sender} (Domain: {sender_domain})\n"
        f"Candidate Origin IP: {candidate_ip}\n"
        f"Evaluated Risk Score: {score}/100 ({verdict})\n"
        f"Triggered Threat Indicators: {triggers_str}\n\n"
        f"--- SANITIZED EMAIL BODY SNIPPET ---\n"
        f"{body_snippet}\n"
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

    # 2. Tier 1: Groq Cloud Provider (3.5s timeout)
    try:
        summary = await generate_groq_briefing(prompt)
        logger.info("Successfully generated threat briefing via Groq cloud engine.")
        return {
            "summary": summary,
            "engine_used": "groq",
            "dlp_active": dlp_active,
            "dlp_security": dlp_security,
        }
    except Exception as groq_err:
        logger.warning(f"Groq provider unavailable or failed ({groq_err}); failing over to Ollama.")

    # 3. Tier 2: Ollama Local Air-Gapped Provider (5.0s timeout)
    try:
        summary = await generate_ollama_briefing(prompt)
        logger.info("Successfully generated threat briefing via Ollama local engine.")
        return {
            "summary": summary,
            "engine_used": "ollama",
            "dlp_active": dlp_active,
            "dlp_security": dlp_security,
        }
    except Exception as ollama_err:
        logger.warning(f"Ollama provider unavailable or failed ({ollama_err}); falling back to deterministic template.")

    # 4. Tier 3: Deterministic Forensic Static Template
    fallback_summary = get_static_briefing_template(
        score=score,
        verdict=verdict,
        penalties=penalties if isinstance(penalties, list) else [],
        sender=sender,
        subject=subject,
    )

    return {
        "summary": fallback_summary,
        "engine_used": "fallback_template",
        "dlp_active": dlp_active,
        "dlp_security": dlp_security,
    }
