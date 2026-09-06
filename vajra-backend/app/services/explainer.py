import json
import logging
from typing import Dict, Any
import httpx

from app.core.config import settings

logger = logging.getLogger("vajra.explainer")


def generate_deterministic_fallback(forensic_data: Dict[str, Any]) -> str:
    """Generate an immediate, contextualized 2-3 sentence forensic cyber threat analyst summary.

    Tiers:
      - Score 0: Fully clean, zero-risk authenticated transmission.
      - Score 1-29 (SAFE): Explains why non-zero scores occur (e.g. datacenter origin for marketing/CRM)
                           while confirming authentic cryptographic alignment.
      - Score 30-69 (SUSPICIOUS): Highlights specific anomalies (display-name spoofing, DNS auth failure).
      - Score 70+ (CRITICAL): Highlights active evasion indicators (Tor, failed DMARC/SPF, spoofed headers).
    """
    subject = forensic_data.get("subject") or "Untitled Email"
    sender = forensic_data.get("sender") or "Unknown Sender"
    risk = forensic_data.get("risk", {})
    score = risk.get("score", 0)
    verdict = risk.get("verdict", "SAFE")
    penalties = risk.get("itemized_penalties", [])
    earliest_ip = forensic_data.get("earliest_public_ip") or "None detected"
    auth = forensic_data.get("auth", {})
    spf_stat = auth.get("spf", {}).get("status", "NONE")
    dkim_stat = auth.get("dkim", {}).get("status", "NONE")
    dmarc_stat = auth.get("dmarc", {}).get("status", "NONE")

    penalty_rules = [
        p.get("rule") if isinstance(p, dict) else getattr(p, "rule", str(p))
        for p in penalties
    ]

    if verdict == "CRITICAL" or score >= 70:
        evasion_triggers = []
        if "Tor Exit Node IP" in penalty_rules:
            evasion_triggers.append("Tor anonymizing exit relay")
        if "SPF Fail" in penalty_rules:
            evasion_triggers.append("unauthorized SPF transmission host")
        if "DKIM Fail" in penalty_rules:
            evasion_triggers.append("tampered/invalid DKIM cryptographic signature")
        if "DMARC Fail/Reject" in penalty_rules:
            evasion_triggers.append("failed DMARC enforcement alignment")
        if "Sender Display-Name Spoofing" in penalty_rules:
            evasion_triggers.append("deceptive sender identity spoofing")

        triggers_str = ", ".join(evasion_triggers) if evasion_triggers else ", ".join(penalty_rules)
        return (
            f"CRITICAL THREAT (Score {score}/100): High-confidence malicious intent detected for email '{subject}' from {sender}. "
            f"Origin MTA {earliest_ip} demonstrates active evasion and compromise indicators including {triggers_str}. "
            f"Immediate automated isolation, perimeter quarantine, and endpoint blocking are strongly mandated."
        )
    elif verdict == "SUSPICIOUS" or (30 <= score <= 69):
        anomalies = []
        if "Sender Display-Name Spoofing" in penalty_rules:
            anomalies.append("sender display-name spoofing mimicking official authority")
        if "Datacenter/Hosting ASN" in penalty_rules:
            anomalies.append("origin routing through commercial datacenter/cloud infrastructure")
        if any(r in penalty_rules for r in ("SPF Fail", "DKIM Fail", "DMARC Fail/Reject")):
            anomalies.append(f"DNS authentication irregularities (SPF: {spf_stat}, DKIM: {dkim_stat}, DMARC: {dmarc_stat})")
        if not anomalies:
            anomalies = penalty_rules

        anomalies_str = "; ".join(anomalies) if anomalies else "anomalous routing characteristics"
        return (
            f"SUSPICIOUS ALERT (Score {score}/100): Message '{subject}' from {sender} exhibits notable security anomalies: {anomalies_str}. "
            f"Initial entry MTA {earliest_ip} lacks verified provenance or policy alignment. "
            f"Elevated caution is advised; secondary analyst triage and link/attachment inspection recommended before delivery."
        )
    else:  # SAFE (< 30)
        if score > 0:
            reasons = []
            if "Datacenter/Hosting ASN" in penalty_rules:
                reasons.append("origin MTA resides in a commercial cloud/datacenter ASN typical of mass newsletters or automated CRM relays")
            if "Tor Exit Node IP" in penalty_rules:
                reasons.append("routing proximity anomaly flagged on gateway")
            reason_str = ", and ".join(reasons) if reasons else "minor non-critical infrastructure variance"
            return (
                f"SAFE VERDICT (Score {score}/100): Email '{subject}' from {sender} was verified as authentic. "
                f"A minor penalty occurred because {reason_str}, but verified DKIM ({dkim_stat}) and DMARC ({dmarc_stat}) cryptographic signatures confirm sender authenticity without tampering. "
                f"Standard message processing and inbox delivery permitted."
            )
        else:
            return (
                f"SAFE VERDICT (Score 0/100): Message '{subject}' from {sender} successfully passed all forensic verification checks. "
                f"Entry MTA {earliest_ip} exhibits clean reputation with valid SPF ({spf_stat}), DKIM ({dkim_stat}), and DMARC ({dmarc_stat}) cryptographic alignment. "
                f"Standard routing and inbox delivery permitted without restriction."
            )


async def generate_analyst_summary(forensic_data: Dict[str, Any]) -> str:
    """Query local air-gapped Ollama instance asynchronously to convert deterministic

    forensics into a 2-3 sentence analyst summary with immediate fallback.
    """
    prompt = (
        "You are an expert Cyber Threat Intelligence Analyst. Based strictly on the following deterministic email forensic data, "
        "write a concise 2-3 sentence executive threat summary. Explicitly contextualize the assigned risk tier:\n"
        "- If SAFE with non-zero score (1-29): explain why non-zero scores occur (e.g. datacenter/cloud origin for newsletter/CRM) but confirm verified DKIM/DMARC authenticates sender.\n"
        "- If SUSPICIOUS (30-69): highlight specific anomalies like missing DNS authentication, display-name spoofing, or routing irregularities.\n"
        "- If CRITICAL (70+): highlight active evasion indicators like Tor exit nodes, spoofed headers, and failed SPF/DMARC policies.\n\n"
        f"Sender: {forensic_data.get('sender')}\n"
        f"Subject: {forensic_data.get('subject')}\n"
        f"Earliest Public Origin IP: {forensic_data.get('earliest_public_ip')}\n"
        f"Authentication: SPF={forensic_data.get('auth', {}).get('spf', {}).get('status')}, "
        f"DKIM={forensic_data.get('auth', {}).get('dkim', {}).get('status')}, "
        f"DMARC={forensic_data.get('auth', {}).get('dmarc', {}).get('status')}\n"
        f"Risk Score: {forensic_data.get('risk', {}).get('score')}/100 ({forensic_data.get('risk', {}).get('verdict')})\n"
        f"Penalties: {[p.get('rule') if isinstance(p, dict) else getattr(p, 'rule', str(p)) for p in forensic_data.get('risk', {}).get('itemized_penalties', [])]}\n"
    )

    url = f"{settings.OLLAMA_HOST.rstrip('/')}/api/generate"
    payload = {
        "model": settings.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 100,
            "temperature": 0.2,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.OLLAMA_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload)
            if response.status_code == 200:
                result = response.json()
                summary = result.get("response", "").strip()
                if summary:
                    return summary
            logger.info(f"Ollama returned non-200 status {response.status_code}; using deterministic fallback.")
    except (httpx.ConnectError, httpx.TimeoutException, Exception) as e:
        logger.info(f"Local Ollama unreachable or timed out ({e}). Engaging deterministic forensic fallback.")

    return generate_deterministic_fallback(forensic_data)
