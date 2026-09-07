"""
VAJRA Forensic Platform - REST API Endpoints Integration Tests
Tests /health, /api/v1/raw, /api/v1/upload, /api/v1/cases, /api/v1/cases/{id}, and /cases/{id}/pdf.
"""

import io
import pytest
from app.storage.memory_store import case_store


@pytest.mark.asyncio
async def test_health_check(async_client):
    res = await async_client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert "telemetry" in data
    assert data["telemetry"]["max_memory_capacity"] == 25


@pytest.mark.asyncio
async def test_analyze_raw_json(async_client):
    raw_email = (
        "From: Alice <alice@example.com>\r\n"
        "To: Bob <bob@example.com>\r\n"
        "Subject: Meeting Notes\r\n"
        "Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        "Message-ID: <msg123@example.com>\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Here are the meeting notes from yesterday."
    )
    payload = {"raw_email": raw_email}
    res = await async_client.post("/api/v1/raw", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["case_id"].startswith("CAS-")
    assert data["subject"] == "Meeting Notes"
    assert data["sender"] == "Alice <alice@example.com>"
    assert data["recipient"] == "Bob <bob@example.com>"
    assert "risk" in data
    assert "verdict" in data
    assert "llm_summary" in data
    assert case_store.count == 1


@pytest.mark.asyncio
async def test_analyze_raw_text_plain(async_client):
    raw_email = (
        "From: admin@alert.com\r\n"
        "To: user@alert.com\r\n"
        "Subject: Critical Patch\r\n"
        "Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        "\r\n"
        "Please apply security update immediately."
    )
    headers = {"Content-Type": "text/plain"}
    res = await async_client.post("/api/v1/raw", content=raw_email.encode("utf-8"), headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["subject"] == "Critical Patch"
    assert case_store.count == 1


@pytest.mark.asyncio
async def test_analyze_upload_eml(async_client):
    eml_bytes = (
        b"From: billing@paypal-notification.com\r\n"
        b"To: target@victim.org\r\n"
        b"Subject: Unauthorized Account Login\r\n"
        b"Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Your account was accessed. Verify at http://194.26.29.111/login now."
    )

    files = {"file": ("alert.eml", io.BytesIO(eml_bytes), "message/rfc822")}
    data = {"dlp_masking": "true"}

    res = await async_client.post("/api/v1/upload", files=files, data=data)
    assert res.status_code == 200
    case_data = res.json()
    assert case_data["case_id"].startswith("CAS-")
    assert case_data["subject"] == "Unauthorized Account Login"


@pytest.mark.asyncio
async def test_get_cases_and_pagination(async_client):
    # Ingest 3 test cases
    for i in range(3):
        raw = f"From: user{i}@example.com\r\nTo: dest@example.com\r\nSubject: Test {i}\r\n\r\nBody {i}"
        await async_client.post("/api/v1/raw", json={"raw_email": raw})

    assert case_store.count == 3

    # Query cases list
    res = await async_client.get("/api/v1/cases?page=1&limit=2")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 2

    # Query single case
    case_id = data["items"][0]["case_id"]
    res_single = await async_client.get(f"/api/v1/cases/{case_id}")
    assert res_single.status_code == 200
    assert res_single.json()["case_id"] == case_id

    # Non-existent case 404
    res_404 = await async_client.get("/api/v1/cases/CAS-NONEXISTENT-999")
    assert res_404.status_code == 404


@pytest.mark.asyncio
async def test_get_case_pdf_stream(async_client):
    raw = "From: hr@corp.com\r\nTo: emp@corp.com\r\nSubject: Bonus\r\n\r\nReview your Q4 bonus."
    create_res = await async_client.post("/api/v1/raw", json={"raw_email": raw})
    case_id = create_res.json()["case_id"]

    pdf_res = await async_client.get(f"/api/v1/cases/{case_id}/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")
    assert len(pdf_res.content) > 500


def test_memory_store_fifo_bound():
    case_store.clear()
    for i in range(30):
        case_store.save_case({"case_id": f"CAS-{i}", "index": i})

    assert case_store.count == 25
    recent = case_store.list_recent_cases()
    # Most recent should be index 29 at position 0
    assert recent[0]["case_id"] == "CAS-29"
    # Oldest retained should be index 5
    assert recent[-1]["case_id"] == "CAS-5"


@pytest.mark.asyncio
async def test_analyze_raw_plain_text_with_quotes_and_newlines(async_client):
    raw_email = (
        'From: "Security Team" <security@example.com>\r\n'
        'To: "User \\"Special\\" Name" <victim@example.com>\r\n'
        'Subject: Urgent "Notice": Account "Status"\r\n'
        'Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n'
        'Content-Type: text/plain\r\n'
        '\r\n'
        'Dear User,\r\n'
        'Your account "XYZ-123" requires "immediate" verification.\r\n'
        'Please review "terms & conditions" here:\r\n'
        'http://example.com/verify\r\n'
        '\r\n'
        'Regards,\r\n'
        '"IT Helpdesk"'
    )
    headers = {"Content-Type": "text/plain"}
    res = await async_client.post("/api/v1/raw", content=raw_email.encode("utf-8"), headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["case_id"].startswith("CAS-")
    assert 'Urgent "Notice"' in data["subject"]


@pytest.mark.asyncio
async def test_dlp_masking_bypassed_liability_alert(async_client):
    raw_email = (
        "From: admin@alert.com\r\n"
        "To: user@alert.com\r\n"
        "Subject: Critical Security Notice\r\n"
        "\r\n"
        "Please note that DLP is disabled for this test."
    )
    res = await async_client.post(
        "/api/v1/raw?dlp_masking=false",
        content=raw_email.encode("utf-8"),
        headers={"Content-Type": "text/plain"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "dlp_security" in data
    dlp_sec = data["dlp_security"]
    assert dlp_sec["status"] == "BYPASSED"
    assert dlp_sec["masking_active"] is False
    assert dlp_sec["liability_disclaimed"] is True
    assert "CRITICAL RISK: DLP Masking was manually bypassed" in dlp_sec["compliance_alert"]


@pytest.mark.asyncio
async def test_dlp_masking_active_default(async_client):
    raw_email = (
        "From: admin@alert.com\r\n"
        "To: user@alert.com\r\n"
        "Subject: Standard Notice\r\n"
        "\r\n"
        "Standard email with active DLP."
    )
    res = await async_client.post("/api/v1/raw", json={"raw_email": raw_email})
    assert res.status_code == 200
    data = res.json()
    assert "dlp_security" in data
    dlp_sec = data["dlp_security"]
    assert dlp_sec["status"] == "ACTIVE"
    assert dlp_sec["masking_active"] is True
    assert dlp_sec["liability_disclaimed"] is False
    assert dlp_sec["compliance_alert"] is None


@pytest.mark.asyncio
async def test_clean_authentic_newsletter_remains_safe(async_client):
    raw_email = (
        "From: Internshala <student@internshala.com>\r\n"
        "To: user@example.com\r\n"
        "Subject: 5 New Internships Matching Your Profile - Apply within 24 hours\r\n"
        "Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        "Message-ID: <internshala-msg-123@internshala.com>\r\n"
        "Authentication-Results: mx.google.com; dkim=pass header.i=@internshala.com; spf=pass (google.com: domain of student@internshala.com designates 54.240.11.12 as permitted sender); dmarc=pass (p=reject)\r\n"
        "Received-SPF: pass (google.com: domain of student@internshala.com designates 54.240.11.12 as permitted sender)\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hi there, apply within 24 hours to secure your internship interview slot.\r\n"
    )
    res = await async_client.post("/api/v1/raw", json={"raw_email": raw_email})
    assert res.status_code == 200
    data = res.json()
    assert data["auth"]["spf"]["status"] == "PASS"
    assert data["auth"]["dkim"]["status"] == "PASS"
    assert data["auth"]["dmarc"]["status"] == "PASS"
    assert data["risk"]["score"] <= 15
    assert data["verdict"] == "SAFE"


@pytest.mark.asyncio
async def test_pdf_report_with_dlp_bypassed_banner(async_client):
    raw = "From: hr@corp.com\r\nTo: emp@corp.com\r\nSubject: Bonus Notice\r\n\r\nReview bonus details."
    create_res = await async_client.post("/api/v1/raw?dlp_masking=false", json={"raw_email": raw})
    case_id = create_res.json()["case_id"]

    pdf_res = await async_client.get(f"/api/v1/cases/{case_id}/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.content.startswith(b"%PDF")
    assert len(pdf_res.content) > 500


@pytest.mark.asyncio
async def test_analyze_raw_free_webmail_financial_lure_endpoint(async_client):
    raw_email = (
        "From: Account Security <billing-security@gmail.com>\r\n"
        "To: victim@example.com\r\n"
        "Subject: Account Suspended: Immediate Payment and Verification Required\r\n"
        "Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        "Authentication-Results: mx.google.com; dkim=pass; spf=pass\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Your account is suspended. Immediate payment and verification required within 24 hours."
    )
    res = await async_client.post("/api/v1/raw", json={"raw_email": raw_email})
    assert res.status_code == 200
    data = res.json()
    # Ensure subject and sender are accurately extracted (fixing No Subject Line / Unknown Sender)
    assert data["subject"] == "Account Suspended: Immediate Payment and Verification Required"
    assert "billing-security@gmail.com" in data["sender"]
    # Score must be at least 55, verdict SUSPICIOUS or MALICIOUS
    assert data["risk"]["score"] >= 55
    assert data["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    rules = [p["rule"] for p in data["risk"]["itemized_penalties"]]
    assert "FREE_WEBMAIL_FINANCIAL_LURE" in rules
    assert "COERCIVE_URGENCY" in rules


@pytest.mark.asyncio
async def test_openapi_dlp_masking_schema_is_required_enum(async_client):
    res = await async_client.get("/api/v1/openapi.json")
    assert res.status_code == 200
    openapi = res.json()
    raw_params = openapi["paths"]["/api/v1/raw"]["post"]["parameters"]
    dlp_param = next(p for p in raw_params if p["name"] == "dlp_masking")
    assert dlp_param["required"] is True
    # Verify DlpOption enum presence
    if "$ref" in dlp_param["schema"]:
        ref_name = dlp_param["schema"]["$ref"].split("/")[-1]
        enum_schema = openapi["components"]["schemas"][ref_name]
        assert enum_schema["enum"] == ["true", "false"]
    else:
        assert dlp_param["schema"]["enum"] == ["true", "false"]
