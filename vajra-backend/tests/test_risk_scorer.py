import pytest
from app.services.risk_scorer import calculate_risk_score


def test_clean_safe_email():
    """An email with valid SPF, DKIM, DMARC, non-Tor, non-datacenter, and no spoofing should be SAFE."""
    auth_matrix = {
        "spf": {"status": "PASS", "details": "SPF aligned"},
        "dkim": {"status": "PASS", "details": "DKIM valid"},
        "dmarc": {"status": "PASS", "policy": "none", "details": "DMARC aligned"},
    }
    result = calculate_risk_score(
        auth_matrix=auth_matrix,
        is_tor_exit=False,
        is_datacenter=False,
        display_name_spoofed=False,
    )
    assert result.score == 0
    assert result.verdict == "SAFE"
    assert len(result.itemized_penalties) == 0


def test_spf_fail_penalty():
    """+25 for SPF Fail."""
    auth_matrix = {
        "spf": {"status": "FAIL", "details": "IP unauthorized"},
        "dkim": {"status": "PASS", "details": "DKIM valid"},
        "dmarc": {"status": "PASS", "policy": "none", "details": "Aligned via DKIM"},
    }
    result = calculate_risk_score(
        auth_matrix=auth_matrix,
        is_tor_exit=False,
        is_datacenter=False,
        display_name_spoofed=False,
    )
    assert result.score == 25
    assert result.verdict == "SAFE"  # <30 is SAFE
    assert any(p.rule == "SPF Fail" and p.penalty == 25 for p in result.itemized_penalties)


def test_dkim_fail_penalty():
    """+20 for DKIM Fail."""
    auth_matrix = {
        "spf": {"status": "PASS", "details": "SPF aligned"},
        "dkim": {"status": "FAIL", "details": "DKIM invalid"},
        "dmarc": {"status": "PASS", "policy": "none", "details": "Aligned via SPF"},
    }
    result = calculate_risk_score(
        auth_matrix=auth_matrix,
        is_tor_exit=False,
        is_datacenter=False,
        display_name_spoofed=False,
    )
    assert result.score == 20
    assert result.verdict == "SAFE"
    assert any(p.rule == "DKIM Fail" and p.penalty == 20 for p in result.itemized_penalties)


def test_dmarc_fail_penalty():
    """+25 for DMARC Fail/Reject."""
    auth_matrix = {
        "spf": {"status": "FAIL", "details": "Unauthorized"},
        "dkim": {"status": "FAIL", "details": "Invalid"},
        "dmarc": {"status": "FAIL", "policy": "reject", "details": "DMARC failed alignment"},
    }
    result = calculate_risk_score(
        auth_matrix=auth_matrix,
        is_tor_exit=False,
        is_datacenter=False,
        display_name_spoofed=False,
    )
    # SPF (25) + DKIM (20) + DMARC (25) = 70 -> CRITICAL
    assert result.score == 70
    assert result.verdict == "CRITICAL"


def test_tor_exit_penalty():
    """+25 for Tor Exit Node IP."""
    auth_matrix = {
        "spf": {"status": "PASS", "details": "SPF aligned"},
        "dkim": {"status": "PASS", "details": "DKIM valid"},
        "dmarc": {"status": "PASS", "policy": "none", "details": "Aligned"},
    }
    result = calculate_risk_score(
        auth_matrix=auth_matrix,
        is_tor_exit=True,
        is_datacenter=False,
        display_name_spoofed=False,
    )
    assert result.score == 25
    assert any(p.rule == "Tor Exit Node IP" and p.penalty == 25 for p in result.itemized_penalties)


def test_datacenter_and_spoofing_suspicious():
    """+15 Datacenter ASN + +15 Display-Name Spoofing = 30 -> SUSPICIOUS (30-69)."""
    auth_matrix = {
        "spf": {"status": "PASS", "details": "SPF aligned"},
        "dkim": {"status": "PASS", "details": "DKIM valid"},
        "dmarc": {"status": "PASS", "policy": "none", "details": "Aligned"},
    }
    result = calculate_risk_score(
        auth_matrix=auth_matrix,
        is_tor_exit=False,
        is_datacenter=True,
        display_name_spoofed=True,
        spoof_reason="Display name impersonates CEO",
    )
    assert result.score == 30
    assert result.verdict == "SUSPICIOUS"
    assert len(result.itemized_penalties) == 2


def test_maximum_ceiling_capped_at_100():
    """All rules triggered: 25+20+25+25+15+15 = 125, should be capped at 100 CRITICAL."""
    auth_matrix = {
        "spf": {"status": "FAIL", "details": "Unauthorized"},
        "dkim": {"status": "FAIL", "details": "Invalid"},
        "dmarc": {"status": "FAIL", "policy": "reject", "details": "Failed"},
    }
    result = calculate_risk_score(
        auth_matrix=auth_matrix,
        is_tor_exit=True,
        is_datacenter=True,
        display_name_spoofed=True,
        spoof_reason="PayPal Security impersonation",
    )
    assert result.score == 100
    assert result.verdict == "CRITICAL"
    assert len(result.itemized_penalties) == 6
