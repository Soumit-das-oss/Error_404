"""
VAJRA Forensic Platform - Text & Social Engineering Analyzer
Detects artificial urgency indicators and Free Webmail authority impersonation lures.
"""

import re
from typing import Dict, Any, List, Optional
from app.core.constants import (
    URGENCY_PATTERNS,
    FINANCIAL_ACCOUNT_LURES,
    FREE_WEBMAIL_DOMAINS,
    IMPERSONATION_TARGET_KEYWORDS,
)


def analyze_text_patterns(
    subject: str,
    body_plain: str,
    sender_display_name: Optional[str] = None,
    sender_domain: Optional[str] = None,
    sender_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Inspect email text and sender attributes for urgency and free webmail impersonation lures."""
    combined_text = f"{subject or ''}\n{body_plain or ''}".lower()

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

    # 3. Detect Free Webmail Impersonation & BEC Lures
    # Occurs when:
    #   a) The actual sending domain is a free public webmail service (e.g. gmail.com, yahoo.com)
    #   AND
    #   b) The email contains urgency keywords OR financial/account lures
    #      (Free webmail accounts are NEVER legitimate corporate newsletters)
    #   OR
    #   c) The display name mimics an authoritative executive, department, or high-profile brand
    #   OR display name embeds an official corporate domain/email
    is_free_webmail_lure = False
    lure_reason = None

    eff_domain = (sender_domain or "").lower().strip()
    disp_name = (sender_display_name or "").lower()
    disp_raw = sender_display_name or ""

    if eff_domain in FREE_WEBMAIL_DOMAINS:
        # Check if display name mimics executive / authority keywords
        for kw in IMPERSONATION_TARGET_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", disp_name):
                is_free_webmail_lure = True
                lure_reason = (
                    f"Sender claims institutional/executive authority ('{disp_raw}') "
                    f"while originating from free webmail provider '{eff_domain}'."
                )
                break

        # Check if display name embeds another domain/email (e.g. "support@company.com" <fraud@gmail.com>)
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

        # Check if urgency or financial/account lure originates from free webmail
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
    }
