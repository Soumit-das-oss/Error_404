import os
from pathlib import Path
from typing import List, Optional, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base backend directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    PROJECT_NAME: str = "VAJRA Forensics - AI-Powered Threat Intelligence Platform (SIH26106)"
    PROBLEM_STATEMENT: str = "SIH26106"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # AI Integration Settings
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "openai/gpt-oss-20b"
    LLM_MODEL: str = "openai/gpt-oss-20b"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_URL: str = "http://localhost:11434/api/generate"
    OLLAMA_MODEL: str = "llama3.2:1b"
    GROQ_TIMEOUT_SECONDS: float = 4.0
    OLLAMA_TIMEOUT_SECONDS: float = 15.0

    # 25 MB Payload Limit (25 * 1024 * 1024 bytes)
    MAX_PAYLOAD_BYTES: int = 26214400

    # GeoIP & Threat Intel File Paths
    DATA_DIR: Path = BASE_DIR / "data"
    GEOLITE2_CITY_PATH: Path = BASE_DIR / "data" / "GeoLite2-City.mmdb"
    GEOLITE2_ASN_PATH: Path = BASE_DIR / "data" / "GeoLite2-ASN.mmdb"
    TOR_EXIT_NODES_PATH: Path = BASE_DIR / "data" / "tor_exit_nodes.txt"
    EXIT_NODES_PATH: Path = BASE_DIR / "data" / "tor_exit_nodes.txt"

    # Defensive DNS Resolution
    DNS_TIMEOUT_SECONDS: float = 3.0

    # Explicit CORS Whitelist for Local React Frontends
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        default_origins = [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    import json
                    parsed = json.loads(v)
                    filtered = [i for i in parsed if i != "*"]
                    return filtered or default_origins
                except Exception:
                    pass
            origins = [i.strip() for i in v.split(",") if i.strip() and i.strip() != "*"]
            return origins or default_origins
        elif isinstance(v, list):
            filtered = [i for i in v if i != "*"]
            return filtered or default_origins
        return default_origins

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )


settings = Settings()
