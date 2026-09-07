"""
VAJRA Forensic Platform - Risk Scorer Unit Tests
Tests deterministic penalty calculations, score ceilings, verdicts, and hard forensic overrides.
"""

import pytest
from app.services.risk_scorer import calculate_risk_score


def test_clean_authentic_email_scores_zero():
    auth = {
        "spf": {"status": "PASS"},
        "dkim": {"status": "PASS"},
        "dmarc": {"status": "PASS", "policy": "reject"},
    }
    result = calculate_risk_score(auth_matrix=auth)
    assert result["score"] == 0
    assert result["verdict"] == "SAFE"
    assert len(result["penalties"]) == 0


def test_authentication_penalties():
    # SPF fail (+15), DKIM fail (+15), DMARC fail (+15)
    auth = {
        "spf": {"status": "FAIL"},
        "dkim": {"status": "FAIL"},
        "dmarc": {"status": "FAIL", "policy": "reject"},
    }
    result = calculate_risk_score(auth_matrix=auth)
    assert result["score"] == 45
    assert result["verdict"] == "SUSPICIOUS"
    assert len(result["penalties"]) == 3


def test_quishing_qr_penalty():
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    result = calculate_risk_score(
        auth_matrix=auth,
        qr_urls=["https://phishing-site.com/login"],
    )
    assert result["score"] == 40
    assert result["verdict"] == "SUSPICIOUS"
    assert any(p["rule"] == "Quishing QR Code" for p in result["penalties"])


def test_deceptive_link_penalty():
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    deceptive = [{
        "anchor_text": "paypal.com",
        "actual_href": "http://evil-site.com",
        "display_domain": "paypal.com",
        "target_domain": "evil-site.com",
    }]
    result = calculate_risk_score(
        auth_matrix=auth,
        deceptive_links=deceptive,
    )
    assert result["score"] == 25
    assert result["verdict"] == "SUSPICIOUS"
    assert any(p["rule"] == "Deceptive Hyperlink" for p in result["penalties"])


def test_free_webmail_lure_and_urgency():
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    result = calculate_risk_score(
        auth_matrix=auth,
        has_urgency=True,
        urgency_matches=["immediate action", "account suspended"],
        is_free_webmail_lure=True,
        lure_reason="Executive impersonation via Gmail",
    )
    # Urgency (+20) + Free Webmail (+35) = 55
    assert result["score"] == 55
    assert result["verdict"] == "SUSPICIOUS"


def test_combined_critical_malicious_score():
    # SPF (+15) + Quishing (+40) + Deceptive (+25) + Urgency (+20) = 100
    auth = {"spf": {"status": "FAIL"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    deceptive = [{"display_domain": "bank.com", "target_domain": "hacker.com"}]
    result = calculate_risk_score(
        auth_matrix=auth,
        deceptive_links=deceptive,
        qr_urls=["http://malicious.org/qr"],
        has_urgency=True,
    )
    assert result["score"] == 100
    assert result["verdict"] == "MALICIOUS"


def test_hard_forensic_override_for_quishing():
    # Score 0 (no other penalties), but QR code is present -> must not be SAFE
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    result = calculate_risk_score(
        auth_matrix=auth,
        qr_urls=["https://example.com/qr"],
    )
    # 40 points is already SUSPICIOUS, but even if quishing was +10 points (hypothetically):
    assert result["verdict"] != "SAFE"


def test_score_bounded_to_100():
    # Trigger all penalties: 15+15+15+25+40+20+35 = 165 -> must cap at 100
    auth = {
        "spf": {"status": "FAIL"},
        "dkim": {"status": "FAIL"},
        "dmarc": {"status": "FAIL", "policy": "reject"},
    }
    deceptive = [{"display_domain": "a", "target_domain": "b"}]
    result = calculate_risk_score(
        auth_matrix=auth,
        deceptive_links=deceptive,
        qr_urls=["http://qr"],
        has_urgency=True,
        is_free_webmail_lure=True,
    )
    assert result["score"] == 100
    assert result["verdict"] == "MALICIOUS"


def test_free_webmail_domain_financial_lure_never_safe():
    # Gmail address with financial lure must never receive newsletter discount even if SPF/DKIM pass
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    result = calculate_risk_score(
        auth_matrix=auth,
        sender_domain="gmail.com",
        has_urgency=True,
        urgency_matches=["account suspended", "verify your account"],
        has_financial_lure=True,
        financial_lure_matches=["payment", "verification required"],
    )
    assert result["score"] >= 55
    assert result["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    rules = [p["rule"] for p in result["penalties"]]
    assert "FREE_WEBMAIL_FINANCIAL_LURE" in rules
    assert "COERCIVE_URGENCY" in rules


def test_corporate_newsletter_receives_discount():
    # Legitimate non-free corporate domain with deadline copy stays SAFE
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    result = calculate_risk_score(
        auth_matrix=auth,
        sender_domain="internshala.com",
        has_urgency=True,
        urgency_matches=["within 24 hours"],
    )
    assert result["score"] == 10
    assert result["verdict"] == "SAFE"
    rules = [p["rule"] for p in result["penalties"]]
    assert "Marketing / Newsletter Time-Sensitive Notice" in rules


def test_benign_qr_code_scores_zero():
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    result = calculate_risk_score(
        auth_matrix=auth,
        qr_urls=["https://google.com"],
        quishing_detected=True,
        is_suspicious_qr=False,
    )
    assert result["score"] == 0
    assert result["verdict"] == "SAFE"
    assert any(p["rule"] == "Benign QR Code Verified" for p in result["penalties"])


def test_pdf_threat_penalties_javascript_and_launch():
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    result_js = calculate_risk_score(
        auth_matrix=auth,
        has_pdf_javascript=True,
    )
    assert result_js["score"] == 35
    assert result_js["verdict"] == "SUSPICIOUS"
    assert any(p["rule"] == "PDF_EMBEDDED_JAVASCRIPT" for p in result_js["penalties"])

    result_launch = calculate_risk_score(
        auth_matrix=auth,
        has_pdf_launch=True,
    )
    assert result_launch["score"] == 45
    assert result_launch["verdict"] == "SUSPICIOUS"
    assert any(p["rule"] == "PDF_MALICIOUS_LAUNCH_ACTION" for p in result_launch["penalties"])


def test_clean_pdf_scores_zero():
    auth = {"spf": {"status": "PASS"}, "dkim": {"status": "PASS"}, "dmarc": {"status": "PASS"}}
    result = calculate_risk_score(
        auth_matrix=auth,
        is_authentic_pdf=True,
    )
    assert result["score"] == 0
    assert result["verdict"] == "SAFE"
    assert any(p["rule"] == "Authentic PDF Document Inspected" for p in result["penalties"])
