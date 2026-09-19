"""
VAJRA Forensic Platform - Local Air-Gapped Ollama LLM Provider
Asynchronous Ollama API client with resilient timeout for cold-start air-gapped inference.
SIH Problem Statement: SIH26106
"""

import inspect
import logging
from typing import Optional, List, Dict, Any
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

DEFAULT_OLLAMA_LOOPBACK = "http://127.0.0.1:11434"
DEFAULT_TAGS_TIMEOUT = 3.0
DEFAULT_INFERENCE_TIMEOUT = 20.0


def normalize_ollama_base_url(raw_url: Optional[str] = None) -> str:
    """Ensure base URL connects to explicit IPv4 loopback (127.0.0.1) instead of localhost.

    Windows network adapters often fail to resolve 'localhost' when network interfaces are disabled in air-gapped simulations.
    """
    endpoint_base = (
        raw_url
        or getattr(settings, "OLLAMA_BASE_URL", None)
        or getattr(settings, "OLLAMA_URL", DEFAULT_OLLAMA_LOOPBACK)
    )
    url = str(endpoint_base).strip().rstrip("/")
    for suffix in ["/api/generate", "/api/chat", "/api/tags"]:
        if url.endswith(suffix):
            url = url[:-len(suffix)].rstrip("/")
    if "localhost" in url:
        url = url.replace("localhost", "127.0.0.1")
    if not url:
        url = DEFAULT_OLLAMA_LOOPBACK
    return url


class OllamaProvider:
    """Resilient local Ollama provider with dynamic model detection and air-gapped loopback fallback."""

    def __init__(self, base_url: Optional[str] = None):
        self._custom_base_url = base_url
        self.last_used_model: Optional[str] = None

    @property
    def base_url(self) -> str:
        return normalize_ollama_base_url(self._custom_base_url)

    def get_base_url(self) -> str:
        return self.base_url

    async def detect_available_models(self, client: httpx.AsyncClient) -> List[str]:
        """Pre-check health query to http://127.0.0.1:11434/api/tags with a 3-second timeout."""
        tags_url = f"{self.get_base_url()}/api/tags"
        available_models: List[str] = []
        try:
            tags_resp = await client.get(tags_url, timeout=DEFAULT_TAGS_TIMEOUT)
            res = tags_resp.raise_for_status()
            if inspect.isawaitable(res):
                await res
            tags_data = tags_resp.json()
            if inspect.isawaitable(tags_data):
                tags_data = await tags_data

            if isinstance(tags_data, dict):
                raw_models = tags_data.get("models", [])
                if isinstance(raw_models, list):
                    for m in raw_models:
                        if isinstance(m, dict):
                            name = m.get("name") or m.get("model")
                            if name and str(name).strip():
                                available_models.append(str(name).strip())
        except Exception as exc:
            logger.warning(
                "Ollama pre-check to '%s' failed or timed out (%s). Proceeding with configured model.",
                tags_url,
                exc,
            )
        return available_models

    async def resolve_model(self, client: httpx.AsyncClient) -> str:
        """Resolve model name, dynamically falling back to first available local model if configured model is absent."""
        configured_model = getattr(settings, "OLLAMA_MODEL", "llama3.2:1b")
        available_models = await self.detect_available_models(client)

        if not available_models:
            self.last_used_model = configured_model
            return configured_model

        # 1. Exact match
        if configured_model in available_models:
            self.last_used_model = configured_model
            return configured_model

        # 2. Tag variations (e.g. "llama3.2" matches "llama3.2:latest" or "llama3.2:1b")
        cfg_base = configured_model.split(":")[0].lower()
        matched = next(
            (m for m in available_models if m.lower() == f"{cfg_base}:latest" or m.lower().startswith(f"{cfg_base}:")),
            None,
        )
        if matched:
            self.last_used_model = matched
            return matched

        # 3. Dynamic Fallback: first available local model found in /api/tags response
        fallback_model = available_models[0]
        logger.warning(
            "Configured Ollama model '%s' not present in local models %s. Automatically falling back to '%s'.",
            configured_model,
            available_models,
            fallback_model,
        )
        self.last_used_model = fallback_model
        return fallback_model

    async def generate_briefing(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """Generate executive threat briefing using local Ollama instance.

        Inspects response for safety refusals or short responses (<25 chars), returning None to trigger Tier 3 fallback.
        Raises:
          Exception on timeout, connection failure, or non-200 responses to trigger failover.
        """
        base_url = self.get_base_url()
        generate_url = f"{base_url}/api/generate"
        sys_content = system_prompt or VAJRA_SOC_SYSTEM_PROMPT

        configured_timeout = float(getattr(settings, "OLLAMA_TIMEOUT_SECONDS", DEFAULT_INFERENCE_TIMEOUT) or DEFAULT_INFERENCE_TIMEOUT)
        inference_timeout = max(15.0, min(25.0, configured_timeout))

        async with httpx.AsyncClient(timeout=inference_timeout) as client:
            target_model = await self.resolve_model(client)

            payload = {
                "model": target_model,
                "prompt": prompt,
                "system": sys_content,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 256,
                },
            }

            response = await client.post(generate_url, json=payload, timeout=inference_timeout)
            res = response.raise_for_status()
            if inspect.isawaitable(res):
                await res

            data = response.json()
            if inspect.isawaitable(data):
                data = await data

            if not isinstance(data, dict):
                raise ValueError("Ollama returned invalid JSON payload.")

            response_text = data.get("response", "").strip()

            if not response_text:
                raise ValueError("Ollama returned an empty response string.")

            normalized_text = response_text.lower()
            if len(response_text) < 25 or any(trigger in normalized_text for trigger in REFUSAL_TRIGGERS):
                logger.warning("Ollama safety refusal detected. Discarding output and falling back to Tier 3 Heuristics.")
                return None

            return response_text


_default_provider = OllamaProvider()


def get_last_used_model() -> Optional[str]:
    """Return the model identifier used in the most recent Ollama inference."""
    return _default_provider.last_used_model


async def generate_ollama_briefing(prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
    """Generate executive threat briefing using local Ollama instance (Tier 2)."""
    return await _default_provider.generate_briefing(prompt, system_prompt=system_prompt)


__all__ = [
    "OllamaProvider",
    "generate_ollama_briefing",
    "get_last_used_model",
    "normalize_ollama_base_url",
    "REFUSAL_TRIGGERS",
    "VAJRA_SOC_SYSTEM_PROMPT",
]
