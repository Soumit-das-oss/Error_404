"""
VAJRA Forensic Platform - Groq Cloud LLM Provider
Asynchronous Groq API client with strict 3.5s timeout.
"""

import logging
from typing import Optional
from groq import AsyncGroq
from app.core.config import settings

logger = logging.getLogger("vajra.ai.groq")


async def generate_groq_briefing(prompt: str) -> str:
    """Generate executive threat briefing using Groq API (llama-3.1-8b-instant).

    Raises:
      ValueError if GROQ_API_KEY is not configured.
      Exception on timeout (3.5s), network failure, or rate limits to trigger failover.
    """
    if not settings.GROQ_API_KEY or not settings.GROQ_API_KEY.strip():
        raise ValueError("GROQ_API_KEY is not configured. Failing over to next engine.")

    client = AsyncGroq(
        api_key=settings.GROQ_API_KEY.strip(),
        timeout=settings.GROQ_TIMEOUT_SECONDS,
    )

    response = await client.chat.completions.create(
        model=settings.LLM_MODEL,
        messages=[
            {
                "role": "system",
                "content": "You are a Senior Digital Forensics SOC Analyst. Write strictly 3 concise sentences as instructed.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        temperature=0.2,
        max_tokens=1024,
    )

    if not response.choices:
        raise ValueError("Groq returned an empty choices list.")

    choice = response.choices[0]
    message = choice.message

    content = message.content or ""
    if not str(content).strip():
        content = (
            getattr(message, "reasoning_content", None)
            or getattr(message, "reasoning", None)
            or ""
        )
        if not content and hasattr(message, "model_extra") and isinstance(message.model_extra, dict):
            content = str(message.model_extra.get("reasoning") or "")

    extracted_str = str(content or "").strip()
    if not extracted_str:
        raise ValueError("Groq returned an empty response string.")

    return extracted_str
