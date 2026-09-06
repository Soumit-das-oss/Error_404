from typing import Dict, Any, List, Optional
from app.schemas.analysis import RiskBreakdownDTO, PenaltyItemDTO


def calculate_risk_score(
    auth_matrix: Dict[str, Any],
    is_tor_exit: bool,
    is_datacenter: bool,
    display_name_spoofed: bool,
    spoof_reason: Optional[str] = None,
) -> RiskBreakdownDTO:
    """Compute deterministic threat score (0-100) and forensic penalty breakdown.

    Deterministic Scoring Rules:
      - +25 SPF Fail
      - +20 DKIM Fail
      - +25 DMARC Fail/Reject
      - +25 Tor Exit Node IP
      - +15 Datacenter/Hosting ASN (e.g., OVH, DigitalOcean, Hetzner, AWS)
      - +15 Sender Display-Name Spoofing

    Verdicts:
      - SAFE: score < 30
      - SUSPICIOUS: 30 - 69
      - CRITICAL: 70+
    """
    total_score = 0
    penalties: List[PenaltyItemDTO] = []

    spf_info = auth_matrix.get("spf", {})
    spf_status = str(spf_info.get("status", "")).upper()

    dkim_info = auth_matrix.get("dkim", {})
    dkim_status = str(dkim_info.get("status", "")).upper()

    dmarc_info = auth_matrix.get("dmarc", {})
    dmarc_status = str(dmarc_info.get("status", "")).upper()
    dmarc_policy = str(dmarc_info.get("policy", "")).lower()

    # Rule 1: SPF Fail (+25)
    if spf_status in ("FAIL", "SOFTFAIL"):
        penalty = 25
        total_score += penalty
        penalties.append(
            PenaltyItemDTO(
                rule="SPF Fail",
                penalty=penalty,
                reason=f"Sender SPF record check evaluated to {spf_status}. IP not permitted.",
            )
        )

    # Rule 2: DKIM Fail (+20)
    if dkim_status == "FAIL":
        penalty = 20
        total_score += penalty
        penalties.append(
            PenaltyItemDTO(
                rule="DKIM Fail",
                penalty=penalty,
                reason="DKIM cryptographic signature present but failed mathematical verification or payload tampered.",
            )
        )

    # Rule 3: DMARC Fail/Reject (+25)
    if dmarc_status == "FAIL" or dmarc_policy in ("reject", "quarantine"):
        penalty = 25
        total_score += penalty
        penalties.append(
            PenaltyItemDTO(
                rule="DMARC Fail/Reject",
                penalty=penalty,
                reason=f"DMARC validation failed or enforcement policy '{dmarc_policy}' mandates rejection.",
            )
        )

    # Rule 4: Tor Exit Node IP (+25)
    if is_tor_exit:
        penalty = 25
        total_score += penalty
        penalties.append(
            PenaltyItemDTO(
                rule="Tor Exit Node IP",
                penalty=penalty,
                reason="Earliest public entry MTA IP matches an active Tor Exit Node proxy relay.",
            )
        )

    # Rule 5: Datacenter/Hosting ASN (+15)
    if is_datacenter:
        penalty = 15
        total_score += penalty
        penalties.append(
            PenaltyItemDTO(
                rule="Datacenter/Hosting ASN",
                penalty=penalty,
                reason="Origin MTA resides in commercial cloud/datacenter ASN (e.g. AWS, OVH, DigitalOcean, Hetzner).",
            )
        )

    # Rule 6: Sender Display-Name Spoofing (+15)
    if display_name_spoofed:
        penalty = 15
        total_score += penalty
        penalties.append(
            PenaltyItemDTO(
                rule="Sender Display-Name Spoofing",
                penalty=penalty,
                reason=spoof_reason or "Display name mimics high-trust authority or embeds mismatching email identity.",
            )
        )

    # Bound score between 0 and 100
    bounded_score = min(100, max(0, total_score))

    # Determine verdict
    if bounded_score < 30:
        verdict = "SAFE"
    elif bounded_score <= 69:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CRITICAL"

    return RiskBreakdownDTO(
        score=bounded_score,
        verdict=verdict,
        itemized_penalties=penalties,
    )
