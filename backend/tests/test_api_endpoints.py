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
    assert "ai_provider" in data
    assert data["ai_provider"] in ("groq", "ollama", "heuristic")
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

    # Verify multipart/form-data is the primary content type for /api/v1/raw
    raw_content = openapi["paths"]["/api/v1/raw"]["post"]["requestBody"]["content"]
    assert list(raw_content.keys())[0] == "multipart/form-data"
    multipart_schema = raw_content["multipart/form-data"]["schema"]
    assert "raw_email" in multipart_schema["properties"]
    assert "attachments" in multipart_schema["properties"]


@pytest.mark.asyncio
async def test_analyze_raw_with_mobile_attachments_image_qr(async_client):
    import qrcode

    # Generate in-memory synthetic QR code image pointing to a quishing URL
    qr_img = qrcode.make("https://fake-login-update.com/login")
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_bytes = qr_buf.getvalue()

    raw_email = (
        "From: IT Support <support@company.com>\r\n"
        "To: employee@company.com\r\n"
        "Subject: Urgent: Multi-Factor Authentication QR Setup\r\n"
        "Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Please scan the attached QR code to re-authenticate your account."
    )

    data = {"raw_email": raw_email}
    files = [
        ("attachments", ("mfa_qr.png", io.BytesIO(qr_bytes), "image/png")),
    ]

    res = await async_client.post("/api/v1/raw", data=data, files=files)
    assert res.status_code == 200
    res_data = res.json()

    # 1. Assert subject and sender are correctly extracted
    assert res_data["subject"] == "Urgent: Multi-Factor Authentication QR Setup"
    assert "support@company.com" in res_data["sender"]

    # 2. Assert mobile attachment is recorded in metadata
    assert len(res_data["attachments"]) == 1
    assert res_data["attachments"][0]["filename"] == "mfa_qr.png"
    assert "image/png" in res_data["attachments"][0]["content_type"]

    # 3. Assert quishing heuristics evaluated
    assert res_data["quishing_detected"] is True
    assert "https://fake-login-update.com/login" in res_data["artifacts"]["qr_code_urls"]

    # 4. Quishing QR Code (+40) penalty must be triggered and verdict cannot be SAFE
    rules = [p["rule"] for p in res_data["risk"]["itemized_penalties"]]
    assert any(r in ("Quishing QR Code", "QUISHING_QR_FOUND") for r in rules)
    assert res_data["risk"]["score"] >= 40
    assert res_data["verdict"] in ("SUSPICIOUS", "MALICIOUS")


@pytest.mark.asyncio
async def test_analyze_raw_pratiksha_dabhekar_gmail_bec_with_attachments(async_client):
    import qrcode

    # Generate synthetic QR code
    qr_img = qrcode.make("https://malicious-gateway.com/verify-account")
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_bytes = qr_buf.getvalue()

    raw_email = (
        "From: Pratiksha Dabhekar <shraddhadabhekar21072011@gmail.com>\r\n"
        "Subject: URGENT: Payment Account Verification Required\r\n"
        "\r\n"
        "Dear user, verify payment immediately."
    )

    data = {"raw_email": raw_email}
    files = [
        ("attachments", ("payment_qr.png", io.BytesIO(qr_bytes), "image/png")),
    ]

    res = await async_client.post("/api/v1/raw", data=data, files=files)
    assert res.status_code == 200
    res_data = res.json()

    # 1. Assert non-null subject and sender extracted
    assert res_data["subject"] == "URGENT: Payment Account Verification Required"
    assert "shraddhadabhekar21072011@gmail.com" in res_data["sender"]
    assert res_data["sender_domain"] == "gmail.com"

    # 2. Assert attachments length >= 1
    assert len(res_data["attachments"]) >= 1
    assert res_data["attachments"][0]["filename"] == "payment_qr.png"

    # 3. Assert quishing detected
    assert res_data["quishing_detected"] is True
    assert "https://malicious-gateway.com/verify-account" in res_data["artifacts"]["qr_code_urls"]

    # 4. Assert risk score >= 55 (with quishing floor >= 60)
    assert res_data["risk"]["score"] >= 55
    assert res_data["verdict"] in ("SUSPICIOUS", "MALICIOUS")

    # 5. Assert BEC and Quishing penalties triggered
    rules = [p["rule"] for p in res_data["risk"]["itemized_penalties"]]
    assert "FREE_WEBMAIL_FINANCIAL_LURE" in rules
    assert "COERCIVE_URGENCY" in rules
    assert any(r in ("QUISHING_QR_FOUND", "Quishing QR Code") for r in rules)


@pytest.mark.asyncio
async def test_benign_qr_code_evaluates_safe(async_client):
    import qrcode

    # Generate benign QR pointing to google.com
    qr_img = qrcode.make("https://google.com")
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_bytes = qr_buf.getvalue()

    raw_email = (
        "From: Corporate Relations <relations@company.com>\r\n"
        "To: employee@company.com\r\n"
        "Subject: Connect with our Official Portal\r\n"
        "Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Scan the QR code to visit our official verified search and resource page."
    )

    data = {"raw_email": raw_email}
    files = [
        ("attachments", ("google_qr.png", io.BytesIO(qr_bytes), "image/png")),
    ]

    res = await async_client.post("/api/v1/raw", data=data, files=files)
    assert res.status_code == 200
    res_data = res.json()

    # Assert quishing is NOT flagged on benign QR code
    assert res_data["quishing_detected"] is False
    assert res_data["risk"]["score"] < 20
    assert res_data["verdict"] == "SAFE"

    rules = [p["rule"] for p in res_data["risk"]["itemized_penalties"]]
    assert "QUISHING_QR_FOUND" not in rules
    assert "Quishing QR Code" not in rules
    assert any(p["rule"] == "Benign QR Code Verified" for p in res_data["risk"]["itemized_penalties"])


@pytest.mark.asyncio
async def test_malicious_quishing_qr_triggers_penalty(async_client):
    import qrcode

    # Generate malicious QR pointing to unencrypted internal/direct IP login portal
    qr_img = qrcode.make("http://192.168.1.50/login")
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_bytes = qr_buf.getvalue()

    raw_email = (
        "From: IT Admin <admin@secure-corp.com>\r\n"
        "To: user@secure-corp.com\r\n"
        "Subject: Security Re-Authentication Notice\r\n"
        "Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Please authenticate using the direct IP terminal QR code."
    )

    data = {"raw_email": raw_email}
    files = [
        ("attachments", ("terminal_qr.png", io.BytesIO(qr_bytes), "image/png")),
    ]

    res = await async_client.post("/api/v1/raw", data=data, files=files)
    assert res.status_code == 200
    res_data = res.json()

    # Assert quishing IS flagged on direct IP / unencrypted login QR
    assert res_data["quishing_detected"] is True
    assert res_data["risk"]["score"] >= 60
    assert res_data["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    rules = [p["rule"] for p in res_data["risk"]["itemized_penalties"]]
    assert any(r in ("QUISHING_QR_FOUND", "Quishing QR Code") for r in rules)


@pytest.mark.asyncio
async def test_clean_pdf_attachment_evaluates_safe(async_client):
    from reportlab.pdfgen import canvas

    # Generate in-memory clean invoice PDF
    pdf_buf = io.BytesIO()
    c = canvas.Canvas(pdf_buf)
    c.drawString(100, 750, "Standard Corporate Invoice #88412")
    c.drawString(100, 730, "Amount: $500.00. Clean accounting telemetry.")
    c.save()
    pdf_bytes = pdf_buf.getvalue()

    raw_email = (
        "From: Accounts Payable <accounts@trusted-vendor.com>\r\n"
        "To: client@company.com\r\n"
        "Subject: Monthly Service Invoice\r\n"
        "Date: Mon, 15 Jan 2026 10:00:00 +0000\r\n"
        "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Attached is your standard monthly service invoice for audit records."
    )

    data = {"raw_email": raw_email}
    files = [
        ("attachments", ("invoice.pdf", io.BytesIO(pdf_bytes), "application/pdf")),
    ]

    res = await async_client.post("/api/v1/raw", data=data, files=files)
    assert res.status_code == 200
    res_data = res.json()

    # Assert clean PDF receives zero threat penalty and evaluates SAFE
    assert res_data["risk"]["score"] < 20
    assert res_data["verdict"] == "SAFE"

    # Assert attachment metadata is cleanly recorded
    assert len(res_data["attachments"]) == 1
    assert res_data["attachments"][0]["filename"] == "invoice.pdf"
    assert len(res_data["attachments"][0]["sha256"]) == 64

    # Assert zero PDF threat rules triggered
    rules = [p["rule"] for p in res_data["risk"]["itemized_penalties"]]
    assert "PDF_EMBEDDED_JAVASCRIPT" not in rules
    assert "PDF_MALICIOUS_LAUNCH_ACTION" not in rules
    assert "PDF_DECEPTIVE_HYPERLINK" not in rules


@pytest.mark.asyncio
async def test_corrupted_truncated_mime_email_pratiksha_dabhekar(async_client):
    raw_corrupted_mime = (
        "From: Pratiksha Dabhekar <shraddhadabhekar21072011@gmail.com>\r\n"
        "Subject: URGENT: Payment Account Verification Required\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="====CORRUPT_BOUNDARY===="\r\n'
        "\r\n"
        "--====CORRUPT_BOUNDARY====\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Dear user, verify payment immediately.\r\n"
        "--====CORRUPT_BOUNDARY====\r\n"
        'Content-Type: application/pdf; name="invoice.pdf"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="invoice.pdf"\r\n'
        "\r\n"
        "!!!INVALID_BASE64_CORRUPTED_BLOCK===\r\n"
        "--====CORRUPT_BOUNDARY====\r\n"
        'Content-Type: image/png; name="empty.png"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        'Content-Disposition: attachment; filename="empty.png"\r\n'
        "\r\n"
        "--====CORRUPT_BOUNDARY====--\r\n"
    )

    res = await async_client.post("/api/v1/raw", json={"raw_email": raw_corrupted_mime})
    assert res.status_code == 200
    res_data = res.json()

    # Assert subject and sender domain extracted without parser crash
    assert res_data["subject"] == "URGENT: Payment Account Verification Required"
    assert res_data["sender_domain"] == "gmail.com"
    assert "shraddhadabhekar21072011@gmail.com" in res_data["sender"]

    # Assert BEC financial lure penalty applied and score floor >= 55
    assert res_data["risk"]["score"] >= 55
    assert res_data["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    rules = [p["rule"] for p in res_data["risk"]["itemized_penalties"]]
    assert "FREE_WEBMAIL_FINANCIAL_LURE" in rules
    assert "COERCIVE_URGENCY" in rules


@pytest.mark.asyncio
async def test_collapsed_single_line_headers_extraction(async_client):
    # Construct an email and collapse all newlines into spaces (browser form-data simulation)
    multiline_email = (
        "Delivered-To: victim@example.com\n"
        "Received: by mail-ej1-f49.google.com with SMTP id e9-20020a170906328900b00a0c4f3d1234\n"
        "From: Pratiksha Dabhekar <pratikshadabhekar44@gmail.com>\n"
        "Date: Mon, 7 Sep 2026 10:00:00 +0000\n"
        "Subject: Urgent: Verify Corporate Billing Account\n"
        "To: victim@example.com\n"
        "Content-Type: text/plain\n"
        "\n"
        "Dear employee, please verify your corporate billing account credentials immediately."
    )
    collapsed_email = multiline_email.replace("\r", "").replace("\n", " ")

    # Verify via JSON payload
    res = await async_client.post("/api/v1/raw", json={"raw_email": collapsed_email})
    assert res.status_code == 200
    res_data = res.json()

    assert res_data["subject"] == "Urgent: Verify Corporate Billing Account"
    assert "pratikshadabhekar44@gmail.com" in res_data["sender"]
    assert res_data["sender_domain"] == "gmail.com"

    # Verify via Form-Data payload (simulating Swagger UI browser form post)
    res_form = await async_client.post("/api/v1/raw", data={"raw_email": collapsed_email})
    assert res_form.status_code == 200
    res_form_data = res_form.json()

    assert res_form_data["subject"] == "Urgent: Verify Corporate Billing Account"
    assert "pratikshadabhekar44@gmail.com" in res_form_data["sender"]
    assert res_form_data["sender_domain"] == "gmail.com"


@pytest.mark.asyncio
async def test_cors_origins_whitelisting(async_client):
    # Test whitelisted React frontend origin (Vite)
    res_vite = await async_client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res_vite.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert res_vite.headers.get("access-control-allow-credentials") == "true"

    # Test CRA / Next.js default origin
    res_cra = await async_client.options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res_cra.headers.get("access-control-allow-origin") == "http://localhost:3000"

    # Test unwhitelisted origin is NOT granted access
    res_disallowed = await async_client.options(
        "/health",
        headers={
            "Origin": "http://malicious-external-origin.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res_disallowed.headers.get("access-control-allow-origin") is None


@pytest.mark.asyncio
async def test_case_id_quote_sanitization(async_client):
    raw_email = (
        "From: test@example.com\r\n"
        "To: user@example.com\r\n"
        "Subject: Test Case Sanitization\r\n"
        "\r\n"
        "Testing quote stripping on case ID endpoints."
    )
    res_post = await async_client.post("/api/v1/raw", data={"raw_email": raw_email})
    assert res_post.status_code == 200
    case_id = res_post.json()["case_id"]

    # 1. Test case retrieval with surrounding double quotes: "CAS-..."
    res_quoted_double = await async_client.get(f'/api/v1/cases/"{case_id}"')
    assert res_quoted_double.status_code == 200
    assert res_quoted_double.json()["case_id"] == case_id

    # 2. Test case retrieval with surrounding single quotes: 'CAS-...'
    res_quoted_single = await async_client.get(f"/api/v1/cases/'{case_id}'")
    assert res_quoted_single.status_code == 200
    assert res_quoted_single.json()["case_id"] == case_id

    # 3. Test PDF download route with quoted case_id
    res_pdf_quoted = await async_client.get(f'/api/v1/cases/"{case_id}"/pdf')
    assert res_pdf_quoted.status_code == 200
    assert res_pdf_quoted.headers["content-type"] == "application/pdf"


@pytest.mark.asyncio
async def test_brand_typosquatting_filipkart_detection(async_client):
    raw_email = (
        "From: order-update@notifications-hub.com\r\n"
        "To: victim@example.com\r\n"
        "Subject: Claim your Big Billion Day Gift\r\n"
        "Authentication-Results: mx.example.com; dkim=pass; spf=pass; dmarc=pass\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html><body>Click here to claim: <a href='https://www.filipkart.com/claim-now'>Claim Deal</a></body></html>"
    )
    res = await async_client.post("/api/v1/raw", data={"raw_email": raw_email})
    assert res.status_code == 200
    data = res.json()

    # Brand typosquatting must force MALICIOUS verdict with score >= 75
    assert data["risk"]["score"] >= 75
    assert data["verdict"] == "MALICIOUS"

    rules = [p["rule"] for p in data["risk"]["itemized_penalties"]]
    assert "TYPOSQUAT_BRAND_IMPERSONATION" in rules

    # Assert deceptive_urls records the typosquatting domain
    deceptive_targets = [d["target_domain"] for d in data["artifacts"]["deceptive_urls"]]
    assert "filipkart.com" in deceptive_targets


@pytest.mark.asyncio
async def test_free_webmail_commercial_lure_flipkart(async_client):
    raw_email = (
        "From: Flipkart Deals <dealsflipkart99@gmail.com>\r\n"
        "To: shopper@example.com\r\n"
        "Subject: Flipkart Big Billion Days - Exclusive Voucher Claim\r\n"
        "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Dear customer, you have won an exclusive voucher worth 5000 Rs for Flipkart Big Billion Days."
    )
    res = await async_client.post("/api/v1/raw", data={"raw_email": raw_email})
    assert res.status_code == 200
    data = res.json()

    assert data["risk"]["score"] >= 75
    assert data["verdict"] == "MALICIOUS"

    rules = [p["rule"] for p in data["risk"]["itemized_penalties"]]
    assert "FREE_WEBMAIL_BRAND_IMPERSONATION" in rules


@pytest.mark.asyncio
async def test_independent_verification_source_and_fallback(async_client):
    raw_email = (
        "From: notifications@google.com\r\n"
        "To: user@example.com\r\n"
        "Subject: Security Account Notice\r\n"
        "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Official security notice from Google."
    )
    res = await async_client.post("/api/v1/raw", data={"raw_email": raw_email})
    assert res.status_code == 200
    data = res.json()

    indep = data.get("independent_verification", {})
    assert "spf" in indep
    assert "dkim" in indep
    assert "dmarc" in indep
    assert indep["spf"]["source"] in ("live_dns", "recorded_mta")
    assert indep["dmarc"]["source"] in ("live_dns", "recorded_mta")


@pytest.mark.asyncio
async def test_pdf_report_itemized_threat_deductions_rendering(async_client):
    import fitz
    from app.services.report_generator import generate_case_pdf

    # 1. Ingest a malicious typosquatted email to generate positive threat penalties
    raw_email = (
        "From: Flipkart Support <support@filipkart.com>\r\n"
        "To: victim@example.com\r\n"
        "Subject: Urgent Account Suspension Notice\r\n"
        "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Please verify your credentials at http://filipkart.com/login immediately."
    )
    res = await async_client.post("/api/v1/raw", data={"raw_email": raw_email})
    assert res.status_code == 200
    data = res.json()
    case_id = data["case_id"]
    assert data["risk"]["score"] >= 75
    assert data["verdict"] == "MALICIOUS"

    # 2. Fetch PDF dossier via GET /api/v1/cases/{case_id}/pdf
    pdf_res = await async_client.get(f"/api/v1/cases/{case_id}/pdf")
    assert pdf_res.status_code == 200
    pdf_bytes = pdf_res.content
    assert pdf_bytes.startswith(b"%PDF")

    # 3. Inspect PDF text: must contain rule code and points, must NOT say Clean Audit
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    all_text = "".join(page.get_text() for page in doc)
    assert "TYPOSQUAT_BRAND_IMPERSONATION" in all_text
    assert "+45" in all_text
    assert "Clean Audit: Zero threat penalties triggered." not in all_text

    # 4. Direct check on clean case (score=0, no positive penalties): must display Clean Audit
    clean_case = {
        "case_id": "CAS-CLEAN-001",
        "sha256": "0" * 64,
        "subject": "Clean Email",
        "sender": "clean@example.com",
        "score": 0,
        "verdict": "SAFE",
        "risk": {"score": 0, "verdict": "SAFE", "itemized_penalties": []},
    }
    clean_pdf = generate_case_pdf(clean_case)
    clean_doc = fitz.open(stream=clean_pdf, filetype="pdf")
    clean_text = "".join(page.get_text() for page in clean_doc)
    assert "Clean Audit: Zero threat penalties triggered." in clean_text



