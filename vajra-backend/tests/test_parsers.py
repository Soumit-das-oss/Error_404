"""
VAJRA Forensic Platform - Parser & Hop Engine Unit Tests
Tests RFC 5322 parsing, bottom-up hop traversal, origin IP pinpointing, and auth header audits.
"""

import pytest
from app.parsers.eml_parser import parse_eml_bytes
from app.parsers.header_engine import parse_hops_and_origin, audit_authentication_headers, is_public_ip


def test_parse_eml_bytes_basic():
    raw_email = (
        b"From: Security Alert <security@paypal-notice.com>\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Immediate Account Verification Required\r\n"
        b"Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        b"Message-ID: <123456@paypal-notice.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please verify your account immediately at http://194.26.29.111/login"
    )

    result = parse_eml_bytes(raw_email)

    assert result["subject"] == "Immediate Account Verification Required"
    assert result["sender_display_name"] == "Security Alert"
    assert result["sender_address"] == "security@paypal-notice.com"
    assert result["sender_domain"] == "paypal-notice.com"
    assert result["recipient"] == "victim@example.com"
    assert result["message_id"] == "<123456@paypal-notice.com>"
    assert "verify your account immediately" in result["body_plain"]
    assert len(result["sha256"]) == 64


def test_parse_eml_bytes_multipart_attachments():
    raw_multipart = (
        b"From: IT Support <support@company.com>\r\n"
        b"To: employee@company.com\r\n"
        b"Subject: Q1 Salary Breakdown\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n'
        b"\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"See attached salary breakdown.\r\n"
        b"--BOUNDARY\r\n"
        b'Content-Type: text/csv; name="salary.csv"\r\n'
        b'Content-Disposition: attachment; filename="salary.csv"\r\n'
        b"\r\n"
        b"Employee,Amount\r\nAlice,5000\r\n"
        b"--BOUNDARY--\r\n"
    )

    result = parse_eml_bytes(raw_multipart)

    assert "See attached salary breakdown." in result["body_plain"]
    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["filename"] == "salary.csv"
    assert att["content_type"] == "text/csv"
    assert b"Alice,5000" in att["payload_bytes"]
    assert len(att["sha256"]) == 64


def test_is_public_ip():
    assert is_public_ip("194.26.29.111") is True
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("192.168.1.100") is False
    assert is_public_ip("172.16.5.1") is False
    assert is_public_ip("invalid-ip") is False


def test_parse_hops_and_origin_ordering():
    # Received headers in email arrive top-down (newest at the top, earliest at the bottom)
    headers = [
        "from mail-relay.internal.net (10.0.0.2) by mx.company.com (10.0.0.1); Mon, 15 Jan 2026 10:02:00 +0000",
        "from outbound.upstream.isp (198.51.100.50) by mail-relay.internal.net (10.0.0.2); Mon, 15 Jan 2026 10:01:00 +0000",
        "from attacker-vps.net (185.220.101.5) by outbound.upstream.isp; Mon, 15 Jan 2026 10:00:00 +0000",
    ]

    hops, earliest_ip = parse_hops_and_origin(headers)

    assert len(hops) == 3
    # Hop #1 should be the bottom-most / chronologically earliest hop
    assert hops[0]["hop_number"] == 1
    assert hops[0]["ip"] == "185.220.101.5"

    # Hop #2
    assert hops[1]["hop_number"] == 2
    assert hops[1]["ip"] == "198.51.100.50"

    # Hop #3
    assert hops[2]["hop_number"] == 3

    # Candidate origin should be the first public IP encountered
    assert earliest_ip == "185.220.101.5"


def test_audit_authentication_headers():
    auth_res = ["mx.google.com; dkim=pass header.i=@legit.com; spf=pass (google.com: domain of sender@legit.com designates 198.51.100.1 as permitted sender); dmarc=pass (p=reject sp=reject dis=none)"]
    received_spf = ["pass (google.com: domain of sender@legit.com designates 198.51.100.1 as permitted sender)"]
    dkim_sigs = ["v=1; a=rsa-sha256; c=relaxed/relaxed; d=legit.com; s=202301;"]

    audit = audit_authentication_headers(auth_res, received_spf, dkim_sigs)

    assert audit["spf"]["status"] == "PASS"
    assert audit["dkim"]["status"] == "PASS"
    assert audit["dmarc"]["status"] == "PASS"

    # Test failure detection
    fail_auth = ["spf=fail smtp.mailfrom=malicious.org; dkim=fail (signature did not verify); dmarc=fail action=reject"]
    audit_fail = audit_authentication_headers(fail_auth, ["fail"], [])

    assert audit_fail["spf"]["status"] == "FAIL"
    assert audit_fail["dkim"]["status"] == "FAIL"
    assert audit_fail["dmarc"]["status"] == "FAIL"
    assert audit_fail["dmarc"]["policy"] == "reject"
