"""
VAJRA Forensic Platform - Deterministic Risk Scorer
Computes strict 0-100 threat score and itemized forensic penalty audit.
"""

from typing import Dict, Any, List, Optional
from app.core.constants import (
    PENALTY_SPF_FAIL,
    PENALTY_DKIM_FAIL,
    PENALTY_DMARC_FAIL,
    PENALTY_DECEPTIVE_LINK,
    PENALTY_QUISHING_QR,
    PENALTY_URGENCY_INDICATORS,
    PENALTY_FREE_WEBMAIL_LURE,
    PENALTY_PDF_JAVASCRIPT,
    PENALTY_PDF_LAUNCH,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    VERDICT_MALICIOUS,
    THRESHOLD_SAFE_MAX,
    THRESHOLD_SUSPICIOUS_MAX,
    FREE_WEBMAIL_DOMAINS,
)


def calculate_risk_score(
    auth_matrix: Dict[str, Any],
    deceptive_links: Optional[List[Dict[str, Any]]] = None,
    qr_urls: Optional[List[str]] = None,
    has_urgency: bool = False,
    urgency_matches: Optional[List[str]] = None,
    is_free_webmail_lure: bool = False,
    lure_reason: Optional[str] = None,
    sender_domain: Optional[str] = None,
    has_financial_lure: bool = False,
    financial_lure_matches: Optional[List[str]] = None,
    quishing_detected: bool = False,
    is_suspicious_qr: bool = True,
    benign_qr_urls: Optional[List[str]] = None,
    has_pdf_javascript: bool = False,
    has_pdf_launch: bool = False,
    pdf_deceptive_links: Optional[List[Dict[str, Any]]] = None,
    is_authentic_pdf: bool = False,
) -> Dict[str, Any]:
    """Calculate deterministic 0-100 threat score based on forensic evidence.

    Penalties:
      - SPF Fail: +15
      - DKIM Fail: +15
      - DMARC Fail: +15
      - Deceptive Link: +25
      - Quishing QR: +40
      - Urgency / Coercive Indicators: +20
      - Free Webmail Financial/BEC Lure: +35

    Verdicts:
      - 0 to 19: SAFE
      - 20 to 59: SUSPICIOUS
      - 60 to 100: MALICIOUS

    Hard Forensic Override:
      - Non-empty qr_urls or deceptive_links enforces minimum verdict of SUSPICIOUS.
    """
    total_score = 0
    penalties: List[Dict[str, Any]] = []

    spf_info = auth_matrix.get("spf", {}) if isinstance(auth_matrix, dict) else {}
    spf_status = str(spf_info.get("status", "")).upper()

    dkim_info = auth_matrix.get("dkim", {}) if isinstance(auth_matrix, dict) else {}
    dkim_status = str(dkim_info.get("status", "")).upper()

    dmarc_info = auth_matrix.get("dmarc", {}) if isinstance(auth_matrix, dict) else {}
    dmarc_status = str(dmarc_info.get("status", "")).upper()
    dmarc_policy = str(dmarc_info.get("policy", "")).lower()

    # 1. SPF Fail (+15)
    if spf_status in ("FAIL", "SOFTFAIL"):
        penalty = PENALTY_SPF_FAIL
        total_score += penalty
        penalties.append({
            "rule": "SPF Authentication Failure",
            "penalty": penalty,
            "reason": f"Sender SPF check evaluated to {spf_status}. IP unauthorized.",
        })

    # 2. DKIM Fail (+15)
    if dkim_status == "FAIL":
        penalty = PENALTY_DKIM_FAIL
        total_score += penalty
        penalties.append({
            "rule": "DKIM Signature Tampering",
            "penalty": penalty,
            "reason": "DKIM cryptographic signature present but failed verification or body modified.",
        })

    # 3. DMARC Fail (+15)
    if dmarc_status in ("FAIL", "SOFTFAIL"):
        penalty = PENALTY_DMARC_FAIL
        total_score += penalty
        policy_note = f" (enforcement policy '{dmarc_policy}' mandates rejection)" if dmarc_policy in ("reject", "quarantine") else ""
        penalties.append({
            "rule": "DMARC Alignment Failure",
            "penalty": penalty,
            "reason": f"DMARC validation failed with status {dmarc_status}{policy_note}. Identifier alignment failed.",
        })

    # 4. Deceptive Link (+25)
    if deceptive_links:
        penalty = PENALTY_DECEPTIVE_LINK
        total_score += penalty
        penalties.append({
            "rule": "Deceptive Hyperlink",
            "penalty": penalty,
            "reason": (
                f"Discovered {len(deceptive_links)} disguised link(s) where anchor text "
                f"mimics legitimate domain '{deceptive_links[0].get('display_domain')}' "
                f"but routes to '{deceptive_links[0].get('target_domain')}'."
            ),
        })

    # 5. Quishing QR (+40) Evaluation
    # Only penalize when QR is actively suspicious (e.g. direct IP, shortener, phishing endpoint).
    # Benign QR codes receive 0 penalty and allow clean SAFE evaluation.
    if quishing_detected:
        if is_suspicious_qr:
            penalty = PENALTY_QUISHING_QR
            total_score += penalty
            penalties.append({
                "rule": "QUISHING_QR_FOUND",
                "penalty": penalty,
                "reason": f"Decoded {len(qr_urls or [1])} malicious embedded visual QR code link(s) leading to deceptive/phishing endpoints.",
            })
            total_score = max(total_score, 60)
        else:
            url_disp = benign_qr_urls[0] if benign_qr_urls else (qr_urls[0] if qr_urls else "Clean QR payload")
            penalties.append({
                "rule": "Benign QR Code Verified",
                "penalty": 0,
                "reason": f"Benign QR Code Verified: {url_disp}",
            })
    elif qr_urls:
        if is_suspicious_qr:
            penalty = PENALTY_QUISHING_QR
            total_score += penalty
            penalties.append({
                "rule": "Quishing QR Code",
                "penalty": penalty,
                "reason": f"Decoded {len(qr_urls)} embedded visual QR code link(s) in visual attachments.",
            })
        else:
            url_disp = qr_urls[0] if qr_urls else "Clean QR payload"
            penalties.append({
                "rule": "Benign QR Code Verified",
                "penalty": 0,
                "reason": f"Benign QR Code Verified: {url_disp}",
            })

    # 6 & 7: Urgency, Free Webmail BEC, & Financial Lure Evaluation
    sender_dom = (sender_domain or "").lower().strip()
    is_free_webmail_domain = sender_dom in FREE_WEBMAIL_DOMAINS
    is_free_webmail_sender = is_free_webmail_domain or is_free_webmail_lure

    all_lure_matches = list(dict.fromkeys((urgency_matches or []) + (financial_lure_matches or [])))
    matches_str = ", ".join(all_lure_matches[:3]) if all_lure_matches else "urgent pressure phrases"
    is_fully_authenticated = (spf_status == "PASS" and dkim_status == "PASS" and dmarc_status == "PASS")

    if is_free_webmail_sender and (has_urgency or has_financial_lure or is_free_webmail_lure):
        # Free Webmail BEC / Phishing Rule:
        # Senders originating from free webmail accounts are NEVER legitimate corporate newsletters.
        # Trigger COERCIVE_URGENCY (+20) and FREE_WEBMAIL_FINANCIAL_LURE (+35).
        # No newsletter discount granted. Score floor >= 55.
        total_score += PENALTY_URGENCY_INDICATORS
        penalties.append({
            "rule": "COERCIVE_URGENCY",
            "penalty": PENALTY_URGENCY_INDICATORS,
            "reason": f"High-pressure psychological trigger or coercive urgency: '{matches_str}'.",
        })

        total_score += PENALTY_FREE_WEBMAIL_LURE
        penalties.append({
            "rule": "FREE_WEBMAIL_FINANCIAL_LURE",
            "penalty": PENALTY_FREE_WEBMAIL_LURE,
            "reason": lure_reason or f"Free webmail provider '{sender_dom or 'public webmail'}' used for financial/account lure.",
        })

        total_score = max(total_score, 55)

    else:
        # Legitimate corporate / non-free domain or standard flow
        if has_urgency:
            if is_fully_authenticated and not is_free_webmail_sender and not deceptive_links and not qr_urls:
                # Clean authentic corporate marketing/newsletter emails with deadlines stay within SAFE tier (0-15)
                penalty = 10
                rule_name = "Marketing / Newsletter Time-Sensitive Notice"
                reason_text = f"Authenticated sender with promotional / newsletter deadline copy: '{matches_str}'."
            else:
                penalty = PENALTY_URGENCY_INDICATORS
                rule_name = "COERCIVE_URGENCY"
                reason_text = f"Detected high-pressure psychological trigger keywords: '{matches_str}'."

            total_score += penalty
            penalties.append({
                "rule": rule_name,
                "penalty": penalty,
                "reason": reason_text,
            })

        if is_free_webmail_lure:
            penalty = PENALTY_FREE_WEBMAIL_LURE
            total_score += penalty
            penalties.append({
                "rule": "FREE_WEBMAIL_FINANCIAL_LURE",
                "penalty": penalty,
                "reason": lure_reason or "Executive or institutional authority claimed from free public webmail account.",
            })

    # 8. Deep PDF Telemetry Analysis
    if has_pdf_launch:
        penalty = PENALTY_PDF_LAUNCH
        total_score += penalty
        penalties.append({
            "rule": "PDF_MALICIOUS_LAUNCH_ACTION",
            "penalty": penalty,
            "reason": "PDF attachment contains dangerous /Launch or /EmbeddedFiles action targeting binary execution.",
        })
    elif has_pdf_javascript:
        penalty = PENALTY_PDF_JAVASCRIPT
        total_score += penalty
        penalties.append({
            "rule": "PDF_EMBEDDED_JAVASCRIPT",
            "penalty": penalty,
            "reason": "PDF attachment contains embedded active /JavaScript or /JS execution stream.",
        })

    if pdf_deceptive_links:
        penalty = PENALTY_DECEPTIVE_LINK
        total_score += penalty
        penalties.append({
            "rule": "PDF_DECEPTIVE_HYPERLINK",
            "penalty": penalty,
            "reason": f"PDF document embeds {len(pdf_deceptive_links)} deceptive hyperlink(s) misrepresenting destination domain.",
        })

    if is_authentic_pdf and not has_pdf_javascript and not has_pdf_launch and not pdf_deceptive_links:
        penalties.append({
            "rule": "Authentic PDF Document Inspected",
            "penalty": 0,
            "reason": "Authentic PDF Document Inspected: standard text and clean links; zero malicious exploitation tags detected.",
        })

    # Bound score strictly to [0, 100]
    bounded_score = min(100, max(0, total_score))

    # Determine Verdict
    if bounded_score <= THRESHOLD_SAFE_MAX:
        verdict = VERDICT_SAFE
    elif bounded_score <= THRESHOLD_SUSPICIOUS_MAX:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_MALICIOUS

    # Hard Forensic Override:
    # Active malicious QR or deceptive links must never receive a SAFE verdict
    has_active_malicious_qr = (quishing_detected or bool(qr_urls)) and is_suspicious_qr
    has_active_pdf_threat = has_pdf_javascript or has_pdf_launch or bool(pdf_deceptive_links)
    if (has_active_malicious_qr or deceptive_links or has_active_pdf_threat) and verdict == VERDICT_SAFE:
        verdict = VERDICT_SUSPICIOUS

    return {
        "score": bounded_score,
        "verdict": verdict,
        "penalties": penalties,
    }
