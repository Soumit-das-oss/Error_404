"""
VAJRA Forensic Platform - Local Air-Gapped Ollama LLM Provider
Asynchronous Ollama API client with resilient 15.0s timeout for cold-start inference.
"""

import logging
from typing import Optional
import httpx
from app.core.config import settings

logger = logging.getLogger("vajra.ai.ollama")

REFUSAL_TRIGGERS = [
    "cannot assist",
    "can't assist",
    "i am unable",
    "as an ai",
    "i cannot fulfill",
    "against my safety",
    "apologize",
]

VAJRA_SOC_SYSTEM_PROMPT = (
    "You are VAJRA-SOC, an automated digital forensics audit engine. "
    "Your task is to produce a concise 2-sentence technical evaluation explaining the observed security posture in clear human language. "
    "Maintain an objective, neutral investigative tone. Do not provide conversational commentary, greetings, or disclaimers."
)


async def generate_ollama_briefing(prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
    """Generate executive threat briefing using local Ollama instance.

    Inspects response for safety refusals or short responses (<25 chars), returning None to trigger Tier 3 fallback.
    Raises:
      Exception on timeout (15.0s), connection failure, or non-200 responses to trigger template fallback.
    """
    endpoint_base = getattr(settings, "OLLAMA_BASE_URL", None) or settings.OLLAMA_URL
    url = f"{str(endpoint_base).rstrip('/')}"
    # If endpoint does not end with /api/generate or /api/chat, append /api/generate
    if not url.endswith("/api/generate"):
        url = f"{url}/api/generate"

    sys_content = system_prompt or VAJRA_SOC_SYSTEM_PROMPT

    payload = {
        "model": settings.OLLAMA_MODEL,
        "prompt": prompt,
        "system": sys_content,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 256,
        },
    }

    async with httpx.AsyncClient(timeout=settings.OLLAMA_TIMEOUT_SECONDS) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        response_text = data.get("response", "").strip()

        if not response_text:
            raise ValueError("Ollama returned an empty response string.")

        normalized_text = response_text.lower()
        if len(response_text) < 25 or any(trigger in normalized_text for trigger in REFUSAL_TRIGGERS):
            logger.warning("Ollama safety refusal detected. Discarding output and falling back to Tier 3 Heuristics.")
            return None

        return response_text
