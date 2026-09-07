"""
VAJRA Forensic Platform - DLP Shield Unit Tests
Tests sensitive PII scrubbing: Credit cards, IBANs, phone numbers, and personal names.
"""

import pytest
from app.services.dlp_shield import sanitize_text


def test_dlp_sanitize_credit_cards():
    text_hyphen = "Please pay using card 4532-1234-5678-9010 immediately."
    cleaned, redacted = sanitize_text(text_hyphen)
    assert redacted is True
    assert "4532-1234-5678-9010" not in cleaned
    assert "[REDACTED_CARD]" in cleaned

    text_space = "Card: 5412 7512 3412 3456."
    cleaned, redacted = sanitize_text(text_space)
    assert redacted is True
    assert "[REDACTED_CARD]" in cleaned


def test_dlp_sanitize_iban():
    text = "Transfer the bounty to IBAN GB29XABC10123456789012 before midnight."
    cleaned, redacted = sanitize_text(text)
    assert redacted is True
    assert "GB29XABC10123456789012" not in cleaned
    assert "[REDACTED_IBAN]" in cleaned


def test_dlp_sanitize_phone_numbers():
    text_intl = "Contact the IT hotline at +1-800-555-0199 for assistance."
    cleaned, redacted = sanitize_text(text_intl)
    assert redacted is True
    assert "+1-800-555-0199" not in cleaned
    assert "[REDACTED_PHONE]" in cleaned


def test_dlp_sanitize_titled_names():
    text = "Authorized by Dr. Robert Oppenheimer and Mr. Johnathan Doe."
    cleaned, redacted = sanitize_text(text)
    assert redacted is True
    assert "Dr. Robert Oppenheimer" not in cleaned
    assert "Mr. Johnathan Doe" not in cleaned
    assert "[REDACTED_NAME]" in cleaned


def test_dlp_sanitize_labeled_names():
    text = "Account Holder: Sarah Connor\nRecipient: Kyle Reese"
    cleaned, redacted = sanitize_text(text)
    assert redacted is True
    assert "Sarah Connor" not in cleaned
    assert "Kyle Reese" not in cleaned
    assert "Account Holder: [REDACTED_NAME]" in cleaned
    assert "Recipient: [REDACTED_NAME]" in cleaned


def test_dlp_no_pii_intact():
    text = "System reboot scheduled at 03:00 UTC. Check apache logs on server."
    cleaned, redacted = sanitize_text(text)
    assert redacted is False
    assert cleaned == text
