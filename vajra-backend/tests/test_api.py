import io
import re
import pytest
import httpx
from app.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert data["service"] == "VAJRA Forensic Platform Backend"
        assert data["telemetry"]["database_connected"] is True


@pytest.mark.asyncio
async def test_auth_registration_and_login():
    """Verify user registration, JWT generation, and /me retrieval."""
    unique_email = "investigator@cyberforensics.gov"
    password = "SuperSecurePassword123!"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Register
        reg_resp = await client.post(
            "/api/v1/auth/register",
            json={"email": unique_email, "password": password},
        )
        assert reg_resp.status_code in (201, 400)  # 201 created or 400 already exists

        # Login via JSON (Frontend / Postman)
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": unique_email, "password": password},
        )
        assert login_resp.status_code == 200
        token_data = login_resp.json()
        assert "access_token" in token_data
        token = token_data["access_token"]

        # Login via Form-Urlencoded (Swagger UI Authorize modal)
        swagger_form_resp = await client.post(
            "/api/v1/auth/login",
            data={"username": unique_email, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert swagger_form_resp.status_code == 200
        assert "access_token" in swagger_form_resp.json()

        # Fetch current user
        me_resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_resp.status_code == 200
        me_data = me_resp.json()
        assert me_data["email"] == unique_email


@pytest.mark.asyncio
async def test_validation_error_jsonable_encoder():
    """Verify that validation errors with malformed data return 422 JSON instead of 500."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Invalid email format in register
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": "not-an-email", "password": "123"},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["success"] is False
        assert data["error"]["code"] == 422
        assert "details" in data["error"]


@pytest.mark.asyncio
async def test_analyze_raw_endpoint_and_db_persistence():
    """Analyze raw email and verify persistence into SQLite database."""
    raw_email_headers = (
        "From: \"CEO Office\" <scammer@sketchy-host.com>\r\n"
        "To: victim@corporation.com\r\n"
        "Subject: Urgent Wire Transfer Required\r\n"
        "Date: Sat, 05 Sep 2026 12:00:00 +0000\r\n"
        "Message-ID: <msg12345@sketchy-host.com>\r\n"
        "Received: from [185.220.101.5] (port=45672 helo=tor-relay)\r\n"
        "    by mx.destination.com with ESMTP; Sat, 05 Sep 2026 12:00:05 +0000"
    )
    raw_body = "Please process this emergency payment immediately."

    payload = {
        "headers": raw_email_headers,
        "body": raw_body,
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/api/v1/analyze/raw", json=payload)
        assert response.status_code == 200
        data = response.json()
        case_id = data["case_id"]
        assert re.match(r"^CAS-\d{8}-[A-Z0-9]{4}$", case_id)
        assert "sha256" in data
        assert data["sender_display_name"] == "CEO Office"
        assert data["earliest_public_ip"] == "185.220.101.5"
        assert len(data["hops"]) >= 1
        assert "risk" in data
        assert data["risk"]["score"] > 0
        assert data["risk"]["verdict"] in ("SAFE", "SUSPICIOUS", "CRITICAL")
        assert "llm_summary" in data

        # Query cases list from SQLite
        list_resp = await client.get("/api/v1/analyze/cases")
        assert list_resp.status_code == 200
        list_data = list_resp.json()
        assert list_data["total"] >= 1
        assert any(c["case_id"] == case_id for c in list_data["items"])

        # Query single case by case_id
        detail_resp = await client.get(f"/api/v1/analyze/cases/{case_id}")
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()
        assert detail_data["case_id"] == case_id
        assert detail_data["sha256"] == data["sha256"]


@pytest.mark.asyncio
async def test_analyze_file_upload_eml():
    """Verify multipart .eml upload endpoint."""
    eml_content = (
        b"From: security@paypal.com.fake\r\n"
        b"To: user@target.org\r\n"
        b"Subject: Security Warning\r\n"
        b"Received: from [194.26.29.112] by mx.target.org; Sat, 05 Sep 2026 12:00:00 +0000\r\n\r\n"
        b"Your account will be suspended unless you click here."
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        files = {"file": ("test_alert.eml", io.BytesIO(eml_content), "message/rfc822")}
        response = await client.post("/api/v1/analyze/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert re.match(r"^CAS-\d{8}-[A-Z0-9]{4}$", data["case_id"])
        assert data["earliest_public_ip"] == "194.26.29.112"


@pytest.mark.asyncio
async def test_case_report_html_endpoint():
    """Verify GET /api/v1/analyze/cases/{case_id}/report returns HTML and 404 for missing."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Test 404 for non-existent case
        missing_resp = await client.get("/api/v1/analyze/cases/CAS-99999999-XXXX/report")
        assert missing_resp.status_code == 404
        assert "text/html" in missing_resp.headers["content-type"]
        assert "Forensic Case Not Found" in missing_resp.text

        # Ingest an email to generate a real case
        raw_payload = {
            "headers": "From: analyst@gov.in\r\nTo: admin@gov.in\r\nSubject: Official Report Test",
            "body": "Evidence text for report generation.",
        }
        create_resp = await client.post("/api/v1/analyze/raw", json=raw_payload)
        assert create_resp.status_code == 200
        case_id = create_resp.json()["case_id"]
        assert re.match(r"^CAS-\d{8}-[A-Z0-9]{4}$", case_id)

        # Query report
        report_resp = await client.get(f"/api/v1/analyze/cases/{case_id}/report")
        assert report_resp.status_code == 200
        assert "text/html" in report_resp.headers["content-type"]
        assert "VAJRA" in report_resp.text
        assert "Download PDF Report" in report_resp.text
        assert "Browser Print" in report_resp.text
        assert "html2pdf.bundle.min.js" in report_resp.text
        assert case_id in report_resp.text
        assert "@media print" in report_resp.text


@pytest.mark.asyncio
async def test_payload_too_large_ceiling():
    """Verify that requests exceeding 25MB are rejected with 413 Content Too Large."""
    large_body = "A" * (26 * 1024 * 1024)
    payload = {
        "headers": "From: test@test.com\r\nTo: test@test.com\r\nSubject: Big",
        "body": large_body,
    }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/api/v1/analyze/raw", json=payload)
        assert response.status_code == 413
        data = response.json()
        assert data["success"] is False
        assert data["error"]["code"] == 413
