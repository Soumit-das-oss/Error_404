import os
from pathlib import Path
from typing import List, Optional, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base backend directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    PROJECT_NAME: str = "VAJRA Forensics - AI-Powered Threat Intelligence Platform"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # AI Integration Settings
    GROQ_API_KEY: Optional[str] = None
    LLM_MODEL: str = "llama-3.1-8b-instant"
    OLLAMA_URL: str = "http://localhost:11434/api/generate"
    OLLAMA_MODEL: str = "llama3.2:1b"
    GROQ_TIMEOUT_SECONDS: float = 3.5
    OLLAMA_TIMEOUT_SECONDS: float = 5.0

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

    # CORS Configuration
    CORS_ORIGINS: List[str] = ["*"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    import json
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )


settings = Settings()
