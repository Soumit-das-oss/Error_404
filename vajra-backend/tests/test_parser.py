import hashlib
import pytest
from app.services.parser import (
    parse_rfc5322_bytes,
    parse_raw_text,
    detect_display_name_spoofing,
)


def test_sha256_cryptographic_evidence_chain():
    raw = b"From: test@example.com\r\nTo: dest@example.com\r\nSubject: Test\r\n\r\nHello"
    expected_sha = hashlib.sha256(raw).hexdigest()

    result = parse_rfc5322_bytes(raw)
    assert result.sha256 == expected_sha
    assert result.sender == "test@example.com"
    assert result.subject == "Test"
    assert result.body_plain.strip() == "Hello"


def test_display_name_spoofing_embedded_email():
    """Fraudulent display name embedding another target address."""
    spoofed, reason = detect_display_name_spoofing(
        display_name="PayPal Support <security@paypal.com>",
        sender_address="attacker@evil-domain.com",
    )
    assert spoofed is True
    assert "security@paypal.com" in reason


def test_display_name_spoofing_brand_mismatch():
    """Executive or brand spoofing against unrelated domain."""
    spoofed, reason = detect_display_name_spoofing(
        display_name="CEO Office Urgent",
        sender_address="hacker@external-mail.ru",
    )
    assert spoofed is True
    assert "claims official authority" in reason


def test_legitimate_display_name_clean():
    """Legitimate display name with matching personal identity."""
    spoofed, reason = detect_display_name_spoofing(
        display_name="Alice Smith",
        sender_address="alice.smith@company.org",
    )
    assert spoofed is False
    assert reason is None
