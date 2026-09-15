"""
VAJRA Forensic Platform - AI Explainer Orchestrator & Auto-Failover Unit Tests
Tests 2-tier failover: Groq -> Ollama -> Deterministic Static Template.
"""

from unittest.mock import patch, MagicMock, AsyncMock
import pytest
from app.services.ai.explainer_orchestrator import generate_threat_explanation


@pytest.mark.asyncio
async def test_ai_failover_tier1_groq_success():
    evidence = {
        "subject": "Urgent Invoice",
        "sender": "billing@fake.com",
        "score": 85,
        "verdict": "MALICIOUS",
        "penalties": [{"rule": "Deceptive Hyperlink", "penalty": 25}],
    }

    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing") as mock_groq:
        mock_groq.return_value = "Groq analysis: Phishing attack identified. Malicious payload link detected. Block domain immediately."

        result = await generate_threat_explanation(evidence, "Check your invoice here.", dlp_masking=False)

        assert result["engine_used"] == "groq"
        assert "Groq analysis" in result["summary"]
        assert result["dlp_active"] is False


@pytest.mark.asyncio
async def test_ai_failover_tier2_ollama_fallback():
    evidence = {
        "subject": "Payroll Update",
        "sender": "hr@fake.com",
        "score": 60,
        "verdict": "MALICIOUS",
        "penalties": [{"rule": "Quishing QR Code", "penalty": 40}],
    }

    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing", side_effect=Exception("Groq timeout")):
        with patch("app.services.ai.explainer_orchestrator.generate_ollama_briefing") as mock_ollama:
            mock_ollama.return_value = "Ollama analysis: Quishing vector observed. QR points to credential harvest. Contain workstation."

            result = await generate_threat_explanation(evidence, "Scan QR code to verify.", dlp_masking=False)

            assert result["engine_used"] == "ollama"
            assert "Ollama analysis" in result["summary"]


@pytest.mark.asyncio
async def test_ai_failover_tier3_static_template_fallback():
    evidence = {
        "subject": "Account Suspension",
        "sender": "admin@warning.com",
        "score": 75,
        "verdict": "MALICIOUS",
        "penalties": [
            {"rule": "SPF Authentication Failure", "penalty": 15},
            {"rule": "Deceptive Hyperlink", "penalty": 25},
        ],
    }

    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing", side_effect=Exception("Groq offline")):
        with patch("app.services.ai.explainer_orchestrator.generate_ollama_briefing", side_effect=Exception("Ollama offline")):
            result = await generate_threat_explanation(evidence, "Click here now.", dlp_masking=False)

            assert result["engine_used"] == "fallback_template"
            assert "CRITICAL" in result["summary"] or "MALICIOUS" in result["summary"]
            assert "SPF Authentication Failure" in result["summary"]


@pytest.mark.asyncio
async def test_ai_dlp_masking_integration():
    evidence = {"subject": "Card verification", "sender": "test@test.com", "score": 10, "verdict": "SAFE"}
    raw_body = "Your credit card 4111-2222-3333-4444 needs revalidation."

    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing", side_effect=Exception("Offline")):
        with patch("app.services.ai.explainer_orchestrator.generate_ollama_briefing", side_effect=Exception("Offline")):
            result = await generate_threat_explanation(evidence, raw_body, dlp_masking=True)

            assert result["dlp_active"] is True
            assert result["engine_used"] == "fallback_template"


@pytest.mark.asyncio
async def test_groq_reasoning_extraction_fallback():
    from app.services.ai.groq_provider import generate_groq_briefing
    from app.core.config import settings

    mock_msg = MagicMock()
    mock_msg.content = None
    mock_msg.reasoning_content = "This is forensic reasoning from a reasoning model."
    mock_msg.reasoning = None
    mock_msg.model_extra = {}

    mock_choice = MagicMock()
    mock_choice.message = mock_msg

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    with patch("app.services.ai.groq_provider.AsyncGroq") as mock_groq_cls:
        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_groq_cls.return_value = mock_client

        with patch.object(settings, "GROQ_API_KEY", "gsk_test_12345"):
            briefing = await generate_groq_briefing("Test prompt")
            assert briefing == "This is forensic reasoning from a reasoning model."


@pytest.mark.asyncio
async def test_groq_empty_string_raises():
    from app.services.ai.groq_provider import generate_groq_briefing
    from app.core.config import settings

    mock_msg = MagicMock()
    mock_msg.content = ""
    mock_msg.reasoning_content = ""
    mock_msg.reasoning = None
    mock_msg.model_extra = {}

    mock_choice = MagicMock()
    mock_choice.message = mock_msg

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    with patch("app.services.ai.groq_provider.AsyncGroq") as mock_groq_cls:
        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_groq_cls.return_value = mock_client

        with patch.object(settings, "GROQ_API_KEY", "gsk_test_12345"):
            with pytest.raises(ValueError, match="Groq returned an empty response string"):
                await generate_groq_briefing("Test prompt")


@pytest.mark.asyncio
async def test_ai_prompt_safe_verdict_generates_clearance_notice():
    evidence = {
        "subject": "Internship Match",
        "sender": "student@internshala.com",
        "sender_domain": "internshala.com",
        "score": 10,
        "verdict": "SAFE",
        "penalties": [],
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
    }
    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing") as mock_groq:
        mock_groq.return_value = "Verified authentic newsletter. Zero malicious indicators found. Clean delivery recommended."
        result = await generate_threat_explanation(evidence, "Apply within 24 hours.", dlp_masking=False)

        assert result["engine_used"] == "groq"
        # Verify the captured prompt passed to LLM
        prompt_passed = mock_groq.call_args[0][0]
        assert "Forensic Case Telemetry:" in prompt_passed
        assert "- Final Verdict: SAFE (Score: 10/100)" in prompt_passed
        assert "- Authentication Claim Audit: SPF=PASS, DKIM=PASS, DMARC=PASS" in prompt_passed
        assert "- Subject: Internship Match" in prompt_passed
        assert "Explain why the message received this verdict based strictly on the telemetry above in exactly 2 concise, factual sentences." in prompt_passed


@pytest.mark.asyncio
async def test_ai_prompt_threat_verdict_generates_incident_triage():
    evidence = {
        "subject": "Immediate Action Required",
        "sender": "admin@phish.com",
        "sender_domain": "phish.com",
        "score": 85,
        "verdict": "MALICIOUS",
        "penalties": [{"rule": "Deceptive Hyperlink", "penalty": 25}],
        "earliest_public_ip": "185.220.101.5",
        "asn": "AS9009 M247 Europe",
    }
    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing") as mock_groq:
        mock_groq.return_value = "Phishing threat detected. Deceptive links observed. Quarantine immediately."
        result = await generate_threat_explanation(evidence, "Click here now.", dlp_masking=False)

        assert result["engine_used"] == "groq"
        prompt_passed = mock_groq.call_args[0][0]
        assert "Forensic Case Telemetry:" in prompt_passed
        assert "- Final Verdict: MALICIOUS (Score: 85/100)" in prompt_passed
        assert "- Observed Infrastructure: IP 185.220.101.5 (ASN: AS9009 M247 Europe)" in prompt_passed
        assert "Deceptive Hyperlink (+25)" in prompt_passed
        assert "- Subject: Immediate Action Required" in prompt_passed
        assert "Explain why the message received this verdict based strictly on the telemetry above in exactly 2 concise, factual sentences." in prompt_passed


@pytest.mark.asyncio
async def test_ai_orchestrator_service_export_and_3tier_failover():
    from app.services.ai_orchestrator import generate_threat_explanation as orch_generate
    evidence = {
        "subject": "System Alert",
        "sender": "sec@corp.com",
        "score": 15,
        "verdict": "SAFE",
        "penalties": [],
    }
    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing", side_effect=Exception("Network disconnected")):
        with patch("app.services.ai.explainer_orchestrator.generate_ollama_briefing", side_effect=Exception("Ollama offline")):
            result = await orch_generate(evidence, "Routine status message.", dlp_masking=True)
            assert result["engine_used"] == "fallback_template"
            assert result["ai_provider"] == "heuristic"
            assert result["summary"].startswith("[Engine: Deterministic Heuristic Fallback]")
            assert result["dlp_security"]["status"] == "ACTIVE"
            assert "CLEARANCE" in result["summary"] or "AUTHENTIC" in result["summary"] or "SAFE" in result["summary"]


@pytest.mark.asyncio
async def test_ai_engine_prefix_and_provider_attribution():
    evidence = {
        "subject": "Test Attributions",
        "sender": "sec@test.org",
        "score": 75,
        "verdict": "MALICIOUS",
        "penalties": [{"rule": "Deceptive Hyperlink", "penalty": 25}],
    }

    # 1. Groq attribution
    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing") as mock_groq:
        mock_groq.return_value = "Phishing attack detected."
        res_groq = await generate_threat_explanation(evidence, "Phishing lure body", dlp_masking=True)
        assert res_groq["ai_provider"] == "groq"
        assert res_groq["summary"].startswith("[Engine: Groq Cloud Reasoning]")

    # 2. Ollama attribution
    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing", side_effect=Exception("Groq down")):
        with patch("app.services.ai.explainer_orchestrator.generate_ollama_briefing") as mock_ollama:
            mock_ollama.return_value = "Air-gapped analysis detected anomaly."
            res_ollama = await generate_threat_explanation(evidence, "Phishing lure body", dlp_masking=True)
            assert res_ollama["ai_provider"] == "ollama"
            assert res_ollama["summary"].startswith("[Engine: Local Air-Gapped Ollama")

    # 3. Deterministic Heuristic Fallback attribution
    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing", side_effect=Exception("Groq down")):
        with patch("app.services.ai.explainer_orchestrator.generate_ollama_briefing", side_effect=Exception("Ollama down")):
            res_fall = await generate_threat_explanation(evidence, "Phishing lure body", dlp_masking=True)
            assert res_fall["ai_provider"] == "heuristic"
            assert res_fall["summary"].startswith("[Engine: Deterministic Heuristic Fallback]")


def test_pdf_report_renders_engine_attribution():
    from app.services.report_generator import generate_case_pdf

    for provider in ["groq", "ollama", "heuristic"]:
        dummy_case = {
            "case_id": f"CAS-TEST-{provider.upper()}",
            "sha256": "abcdef0123456789" * 4,
            "subject": f"Security Notice ({provider})",
            "sender": "alert@example.com",
            "sender_display_name": "Security Alert",
            "earliest_public_ip": "1.2.3.4",
            "message_id": "<test@example.com>",
            "score": 45,
            "verdict": "SUSPICIOUS",
            "ai_provider": provider,
            "llm_summary": f"[Engine: {provider.capitalize()}] Suspicious activity observed across relays.",
            "auth": {
                "spf": {"status": "PASS", "details": "v=spf1 include:_spf.google.com ~all"},
                "dkim": {"status": "PASS", "details": "Signature verified"},
                "dmarc": {"status": "PASS", "details": "p=reject"},
            },
            "hops": [
                {"hop_number": 1, "ip": "1.2.3.4", "city": "Mumbai", "country": "India", "asn": 13335, "asn_org": "Cloudflare", "is_tor_exit": False, "delay_seconds": 1.2}
            ],
            "risk": {
                "score": 45,
                "verdict": "SUSPICIOUS",
                "penalties": [{"rule": "Urgency Lure", "penalty": 20, "reason": "High urgency keywords detected"}],
            },
            "attachments": [
                {"filename": "invoice.pdf", "content_type": "application/pdf", "size_bytes": 1024, "sha256": "1234567890abcdef"}
            ],
            "dlp_security": {"status": "ACTIVE", "masking_active": True},
        }
        pdf_bytes = generate_case_pdf(dummy_case)
        assert pdf_bytes.startswith(b"%PDF")
        assert len(pdf_bytes) > 1000


@pytest.mark.asyncio
async def test_ollama_safety_refusal_triggers_fallback_to_heuristic():
    evidence = {
        "subject": "Wire Transfer Notice",
        "sender": "ceo@impersonate.com",
        "score": 90,
        "verdict": "MALICIOUS",
        "penalties": [{"rule": "Free Webmail BEC", "penalty": 40}],
    }

    refusal_samples = [
        "I cannot assist with this request as an AI.",
        "I apologize, I am unable to analyze this email against my safety guidelines.",
        "As an AI, I cannot fulfill this request.",
        "I can't assist with cyber threats or malicious analysis.",
        "Against my safety rules.",
        "Short",  # < 25 chars
    ]

    for refusal_output in refusal_samples:
        with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing", side_effect=Exception("Groq offline")):
            with patch("app.services.ai.explainer_orchestrator.generate_ollama_briefing") as mock_ollama:
                mock_ollama.return_value = refusal_output
                result = await generate_threat_explanation(evidence, "Send the funds now.", dlp_masking=True)

                assert result["engine_used"] == "fallback_template"
                assert result["ai_provider"] == "heuristic"
                assert result["summary"].startswith("[Engine: Deterministic Heuristic Fallback]")
                assert "[Engine: Local Air-Gapped Ollama]" not in result["summary"]
                assert refusal_output not in result["summary"]


@pytest.mark.asyncio
async def test_ollama_provider_direct_refusal_and_short_response():
    from app.services.ai.ollama_provider import generate_ollama_briefing

    mock_resp_refusal = MagicMock()
    mock_resp_refusal.json.return_value = {"response": "I cannot assist with evaluating security risks."}
    mock_resp_refusal.raise_for_status = MagicMock()

    mock_resp_short = MagicMock()
    mock_resp_short.json.return_value = {"response": "Hello"}
    mock_resp_short.raise_for_status = MagicMock()

    mock_resp_valid = MagicMock()
    mock_resp_valid.json.return_value = {
        "response": "The email passed SPF and DKIM with verified origin MTA from corporate infrastructure."
    }
    mock_resp_valid.raise_for_status = MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        # 1. Refusal trigger -> returns None
        mock_client.post.return_value = mock_resp_refusal
        res = await generate_ollama_briefing("Test prompt")
        assert res is None

        # 2. Short response (< 25 chars) -> returns None
        mock_client.post.return_value = mock_resp_short
        res = await generate_ollama_briefing("Test prompt")
        assert res is None

        # 3. Valid response -> returns string
        mock_client.post.return_value = mock_resp_valid
        res = await generate_ollama_briefing("Test prompt")
        assert res == "The email passed SPF and DKIM with verified origin MTA from corporate infrastructure."

