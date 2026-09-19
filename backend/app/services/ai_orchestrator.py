"""
VAJRA Forensic Platform - Offline-First 3-Tier AI Threat Intelligence Orchestrator
SIH Problem Statement: SIH26106

Manages DLP PII sanitization and guaranteed 3-tier failover with engine attribution:
  Tier 1: Cloud LLM (Groq Cloud API with 4.0s timeout -> [Engine: Groq Cloud Reasoning])
  Tier 2: Local Offline LLM (Ollama instance with 15-25s timeout -> [Engine: Local Air-Gapped Ollama])
  Tier 3: Deterministic Forensic Static Heuristic Briefing -> [Engine: Deterministic Heuristic Fallback]

Guarantees zero crashes and unhandled exceptions even in completely disconnected environments.
"""

from app.services.ai.explainer_orchestrator import (
    generate_threat_explanation,
    generate_groq_briefing,
    generate_ollama_briefing,
    logger,
)

__all__ = [
    "generate_threat_explanation",
    "generate_groq_briefing",
    "generate_ollama_briefing",
    "logger",
]
