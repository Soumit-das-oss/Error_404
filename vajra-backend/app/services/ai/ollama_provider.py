"""
VAJRA Forensic Platform - Local Air-Gapped Ollama LLM Provider
Asynchronous Ollama API client with strict 5.0s timeout.
"""

import logging
import httpx
from app.core.config import settings

logger = logging.getLogger("vajra.ai.ollama")


async def generate_ollama_briefing(prompt: str) -> str:
    """Generate executive threat briefing using local Ollama instance.

    Raises:
      Exception on timeout (5.0s), connection failure, or non-200 responses to trigger template fallback.
    """
    url = f"{settings.OLLAMA_URL.rstrip('/')}"
    # If endpoint does not end with /api/generate or /api/chat, append /api/generate
    if not url.endswith("/api/generate"):
        url = f"{url}/api/generate"

    payload = {
        "model": settings.OLLAMA_MODEL,
        "prompt": prompt,
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

        return response_text
