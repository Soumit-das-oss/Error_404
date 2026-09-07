"""
VAJRA Forensic Platform - Data Loss Prevention (DLP) Shield
Anonymizes sensitive Personally Identifiable Information (PII), banking credentials,
and phone numbers before sending telemetry to cloud or local LLM inference engines.
"""

from typing import Tuple
from app.core.constants import (
    REGEX_CREDIT_CARD,
    REGEX_IBAN,
    REGEX_PHONE,
    REGEX_NAME_LABELS,
    REGEX_NAME_TITLES,
)


def sanitize_text(text: str) -> Tuple[str, bool]:
    """Scrub sensitive PII from email text and return (sanitized_text, was_redacted).

    Replaces:
      - Credit Card Numbers -> [REDACTED_CARD]
      - International Bank Account Numbers (IBAN) -> [REDACTED_IBAN]
      - Phone Numbers -> [REDACTED_PHONE]
      - Personal Names (preceded by titles or labels) -> [REDACTED_NAME]
    """
    if not text:
        return "", False

    sanitized = text
    was_redacted = False

    # 1. Credit Cards
    new_text, count = REGEX_CREDIT_CARD.subn("[REDACTED_CARD]", sanitized)
    if count > 0:
        was_redacted = True
        sanitized = new_text

    # 2. IBAN
    new_text, count = REGEX_IBAN.subn("[REDACTED_IBAN]", sanitized)
    if count > 0:
        was_redacted = True
        sanitized = new_text

    # 3. Phone Numbers
    new_text, count = REGEX_PHONE.subn("[REDACTED_PHONE]", sanitized)
    if count > 0:
        was_redacted = True
        sanitized = new_text

    # 4. Form Labeled Names (e.g. "Customer: Johnathan Doe" -> "Customer: [REDACTED_NAME]")
    def _replace_name_label(match):
        full_match = match.group(0)
        name_part = match.group(1)
        return full_match.replace(name_part, "[REDACTED_NAME]")

    new_text, count = REGEX_NAME_LABELS.subn(_replace_name_label, sanitized)
    if count > 0:
        was_redacted = True
        sanitized = new_text

    # 5. Titled Names (e.g. "Mr. John Smith", "Dr. Jane Doe")
    new_text, count = REGEX_NAME_TITLES.subn("[REDACTED_NAME]", sanitized)
    if count > 0:
        was_redacted = True
        sanitized = new_text

    return sanitized, was_redacted
