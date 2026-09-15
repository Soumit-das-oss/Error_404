"""
VAJRA Forensic Platform - Groq Cloud LLM Provider
Strictly formatted JSON threat analysis powered by Groq and llama3-70b-8192.
"""

import json
import logging
from typing import Optional
from groq import Groq
from app.core.config import settings
from app.schemas.analysis import ThreatAnalysisReport

logger = logging.getLogger("vajra.ai.groq")

SYSTEM_PROMPT = """
You are an elite cybersecurity forensic analyst explaining a threat.
Analyze the following email payload and output ONLY a valid JSON object matching this exact structure:
{
"verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
"tldr": "One simple sentence explaining the core threat or lack thereof.",
"red_flags": [
"Bullet point 1 explaining a specific danger simply.",
"Bullet point 2 explaining a specific danger simply."
],
"action": "One direct sentence on what the user should do next."
}
"""


def get_fallback_report(reason: str = "Forensic Heuristic Engine", evidence: Optional[dict] = None) -> ThreatAnalysisReport:
    """Safe fallback report dynamically derived from forensic evidence."""
    verdict = "SUSPICIOUS"
    score = 65
    penalties = []
    if isinstance(evidence, dict):
        raw_score = evidence.get("score", 0)
        verdict = evidence.get("verdict") or ("MALICIOUS" if raw_score > 60 else "SUSPICIOUS" if raw_score > 20 else "SAFE")
        score = raw_score
        raw_penalties = evidence.get("penalties", [])
        if isinstance(raw_penalties, list):
            for p in raw_penalties:
                if isinstance(p, dict):
                    penalties.append(p.get("reason") or p.get("rule") or str(p))
                elif p:
                    penalties.append(str(p))

    if verdict == "MALICIOUS":
        tldr = f"Forensic engine identified critical threat indicators and deceptive vectors (Risk Score: {score}/100)."
        red_flags = penalties[:3] if penalties else [
            "Deceptive hyperlink or brand impersonation identified in transmission payload.",
            "Cryptographic signature validation failure or unauthorized sending MTA."
        ]
        action = "Quarantine and delete this transmission immediately; do not interact with links or attachments."
    elif verdict == "SUSPICIOUS":
        tldr = f"Forensic engine detected anomalous routing and unverified transmission parameters (Risk Score: {score}/100)."
        red_flags = penalties[:3] if penalties else [
            "Inconsistent reverse DNS or missing cryptographic authentication records.",
            "Elevated urgency or behavioral pressure triggers detected."
        ]
        action = "Verify sender authenticity through an out-of-band channel before taking action."
    else:
        tldr = "Transmission passed cryptographic authentication with clean forensic routing."
        red_flags = ["No critical threat indicators or malicious vectors discovered."]
        action = "Email transmission is deemed safe for regular processing."

    return ThreatAnalysisReport(
        verdict=verdict,
        tldr=tldr,
        red_flags=red_flags,
        action=action
    )


def analyze_threat_with_groq(payload_text: str, evidence: Optional[dict] = None) -> ThreatAnalysisReport:
    """Execute Groq inference using llama3-70b-8192 with strict JSON response format.

    Initializes Groq client with GROQ_API_KEY from settings/environment,
    enforces JSON response format, and returns a validated ThreatAnalysisReport.
    """
    api_key = settings.GROQ_API_KEY
    if not api_key or not api_key.strip():
        logger.info("GROQ_API_KEY not configured in environment; utilizing deterministic heuristic threat report.")
        return get_fallback_report("GROQ_API_KEY unconfigured", evidence=evidence)

    try:
        # Task 1: Client initialized using GROQ_API_KEY from environment/settings
        client = Groq(api_key=api_key.strip())

        # Task 3: Call Groq API with llama3-70b-8192 and strict JSON response_format
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT.strip(),
                },
                {
                    "role": "user",
                    "content": f"Analyze the following email transmission:\n\n{payload_text[:15000]}",
                },
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )

        if not response.choices:
            logger.warning("Groq returned an empty choices array; using fallback.")
            return get_fallback_report("Empty response from Groq")

        raw_content = response.choices[0].message.content or ""
        raw_content = raw_content.strip()

        if not raw_content:
            logger.warning("Groq response message content was empty; using fallback.")
            return get_fallback_report("Empty message content")

        # Task 4: json.loads() and validate into ThreatAnalysisReport model
        data = json.loads(raw_content)

        # Normalize verdict to uppercase
        if "verdict" in data and isinstance(data["verdict"], str):
            v = data["verdict"].upper()
            if v in ("SAFE", "SUSPICIOUS", "MALICIOUS"):
                data["verdict"] = v
            else:
                data["verdict"] = "SUSPICIOUS"

        # Ensure red_flags is a list of strings
        if not isinstance(data.get("red_flags"), list):
            data["red_flags"] = [str(data.get("red_flags") or "Anomalous traits detected.")]
        else:
            data["red_flags"] = [str(rf) for rf in data["red_flags"] if rf]

        if not data["red_flags"]:
            data["red_flags"] = ["No specific threat indicators flagged."]

        return ThreatAnalysisReport.model_validate(data)

    except Exception as exc:
        logger.error(f"Groq API inference or JSON deserialization failed: {exc}", exc_info=True)
        return get_fallback_report(str(exc), evidence=evidence)


async def analyze_threat_with_groq_async(payload_text: str, evidence: Optional[dict] = None) -> ThreatAnalysisReport:
    """Asynchronous wrapper for non-blocking FastAPI execution."""
    import asyncio
    return await asyncio.to_thread(analyze_threat_with_groq, payload_text, evidence=evidence)
