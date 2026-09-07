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
    }
    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing") as mock_groq:
        mock_groq.return_value = "Verified authentic newsletter. Zero malicious indicators found. Permit delivery."
        result = await generate_threat_explanation(evidence, "Apply within 24 hours.", dlp_masking=False)

        assert result["engine_used"] == "groq"
        # Verify the captured prompt passed to LLM
        prompt_passed = mock_groq.call_args[0][0]
        assert "PASSED cryptographic authentication (SPF/DKIM/DMARC)" in prompt_passed
        assert "DO NOT declare this message as phishing, malware, or an attack" in prompt_passed
        assert "SAFE risk score of 10/100" in prompt_passed
        assert "Permit inbox delivery with standard telemetry logging" in prompt_passed


@pytest.mark.asyncio
async def test_ai_prompt_threat_verdict_generates_incident_triage():
    evidence = {
        "subject": "Immediate Action Required",
        "sender": "admin@phish.com",
        "sender_domain": "phish.com",
        "score": 85,
        "verdict": "MALICIOUS",
        "penalties": [{"rule": "Deceptive Hyperlink", "penalty": 25}],
    }
    with patch("app.services.ai.explainer_orchestrator.generate_groq_briefing") as mock_groq:
        mock_groq.return_value = "Phishing threat detected. Deceptive links observed. Quarantine immediately."
        result = await generate_threat_explanation(evidence, "Click here now.", dlp_masking=False)

        assert result["engine_used"] == "groq"
        prompt_passed = mock_groq.call_args[0][0]
        assert "potential email threat was detected with a risk score of 85/100 (MALICIOUS)" in prompt_passed
        assert "Immediate SOC containment action (quarantine, block sender/IP)" in prompt_passed
