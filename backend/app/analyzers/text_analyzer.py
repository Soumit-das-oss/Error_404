"""
VAJRA Forensic Platform - Text & Social Engineering Analyzer
Detects artificial urgency indicators and Free Webmail authority impersonation lures.
"""

from typing import Dict, Any, List, Optional
import re
from app.core.constants import (
    URGENCY_PATTERNS,
    FINANCIAL_ACCOUNT_LURES,
    COMMERCIAL_BRAND_LURES,
    FREE_WEBMAIL_DOMAINS,
    IMPERSONATION_TARGET_KEYWORDS,
)
from app.services.detectors.brand_registry import BRAND_TOKENS, PROTECTED_BRANDS


def analyze_text_patterns(
    subject: str,
    body_plain: str,
    sender_display_name: Optional[str] = None,
    sender_domain: Optional[str] = None,
    sender_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect email text and sender attributes for urgency, commercial lures, and header forgery."""
    combined_text = f"{subject or ''}\n{body_plain or ''}".lower()
    eff_domain = (sender_domain or "").lower().strip()
    disp_name = (sender_display_name or "").lower()
    disp_raw = sender_display_name or ""

    # 1. Detect Urgency Keywords
    matched_urgency: List[str] = []
    for pattern in URGENCY_PATTERNS:
        if pattern in combined_text:
            matched_urgency.append(pattern)

    has_urgency = len(matched_urgency) > 0

    # 2. Detect Financial & Account Lures
    matched_financial: List[str] = []
    for pattern in FINANCIAL_ACCOUNT_LURES:
        if pattern in combined_text:
            matched_financial.append(pattern)

    has_financial_lure = len(matched_financial) > 0

    # 3. Detect Commercial Brand Lures
    matched_commercial: List[str] = []
    for pattern in COMMERCIAL_BRAND_LURES:
        if pattern in combined_text:
            matched_commercial.append(pattern)

    is_free_webmail_brand_impersonation = False
    brand_impersonation_reason = None

    if eff_domain in FREE_WEBMAIL_DOMAINS and matched_commercial:
        is_free_webmail_brand_impersonation = True
        comm_str = ", ".join(matched_commercial[:3])
        brand_impersonation_reason = (
            f"Free webmail provider '{eff_domain}' used to distribute commercial enterprise lures: '{comm_str}'."
        )

    # 4. Detect In-Body Header Forgery (contradicting envelope sender)
    has_in_body_header_spoofing = False
    in_body_spoof_detail = None

    if body_plain:
        for line in body_plain.splitlines():
            line_clean = line.strip()
            m = re.match(r"^(?:\*|_)?(?:from|sender)\s*(?:\*|_)?\s*:\s*(?:\*|_)?(.+)$", line_clean, re.IGNORECASE)
            if m:
                header_val = m.group(1).strip().strip("*_")
                embedded_email = re.search(r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", header_val)
                if embedded_email:
                    claimed_email = embedded_email.group(0).lower()
                    claimed_domain = embedded_email.group(1).lower()
                    if sender_address and claimed_email != sender_address.lower():
                        has_in_body_header_spoofing = True
                        in_body_spoof_detail = (
                            f"In-body header forgery detected: fake header '{line_clean[:80]}' "
                            f"claims sender '{claimed_email}' contradicting envelope sender '{sender_address}'."
                        )
                        break
                    elif eff_domain and claimed_domain != eff_domain:
                        has_in_body_header_spoofing = True
                        in_body_spoof_detail = (
                            f"In-body header forgery detected: fake header '{line_clean[:80]}' "
                            f"claims domain '{claimed_domain}' contradicting envelope domain '{eff_domain}'."
                        )
                        break
                else:
                    header_lower = header_val.lower()
                    for token in BRAND_TOKENS:
                        if token in header_lower and eff_domain in FREE_WEBMAIL_DOMAINS:
                            has_in_body_header_spoofing = True
                            in_body_spoof_detail = (
                                f"In-body header forgery detected: fake header '{line_clean[:80]}' "
                                f"impersonates brand '{token}' while sent from free webmail '{eff_domain}'."
                            )
                            break
                    if has_in_body_header_spoofing:
                        break

    # 5. Detect Free Webmail Impersonation & BEC Lures
    is_free_webmail_lure = False
    lure_reason = None

    if eff_domain in FREE_WEBMAIL_DOMAINS:
        for kw in IMPERSONATION_TARGET_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", disp_name):
                is_free_webmail_lure = True
                lure_reason = (
                    f"Sender claims institutional/executive authority ('{disp_raw}') "
                    f"while originating from free webmail provider '{eff_domain}'."
                )
                break

        if not is_free_webmail_lure:
            embedded_email_match = re.search(r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", disp_raw)
            if embedded_email_match:
                embedded_domain = embedded_email_match.group(1).lower()
                if embedded_domain != eff_domain and embedded_domain not in FREE_WEBMAIL_DOMAINS:
                    is_free_webmail_lure = True
                    lure_reason = (
                        f"Display name disguises sender as '{embedded_domain}' "
                        f"while transmitting via free webmail '{eff_domain}'."
                    )

        if not is_free_webmail_lure and (has_urgency or has_financial_lure):
            is_free_webmail_lure = True
            triggers = list(dict.fromkeys(matched_financial + matched_urgency))
            trigger_str = ", ".join(triggers[:3]) if triggers else "financial/urgency keywords"
            lure_reason = (
                f"Free webmail address ({eff_domain}) transmitting financial or account lure ({trigger_str})."
            )

    return {
        "has_urgency": has_urgency,
        "urgency_matches": matched_urgency,
        "has_financial_lure": has_financial_lure,
        "financial_lure_matches": matched_financial,
        "is_free_webmail_lure": is_free_webmail_lure,
        "lure_reason": lure_reason,
        "is_free_webmail_brand_impersonation": is_free_webmail_brand_impersonation,
        "commercial_matches": matched_commercial,
        "brand_impersonation_reason": brand_impersonation_reason,
        "has_in_body_header_spoofing": has_in_body_header_spoofing,
        "in_body_spoof_detail": in_body_spoof_detail,
    }
