import json
from pathlib import Path
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base backend directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    PROJECT_NAME: str = "VAJRA Email Threat Detection & Forensic Platform"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # Database Connection URL (SQLite default for zero RAM local dev)
    DATABASE_URL: str = "sqlite+aiosqlite:///./vajra.db"

    # Cryptographic JWT Settings
    SECRET_KEY: str = "vajra_super_secret_cryptographic_jwt_key_2026_sih_hackathon_secure"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # 25 MB Payload Limit (25 * 1024 * 1024 bytes)
    MAX_PAYLOAD_BYTES: int = 26214400

    # Local Air-Gapped LLM Reasoning (Ollama)
    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2:1b"
    OLLAMA_TIMEOUT_SECONDS: float = 4.0

    # GeoIP & Threat Intel File Paths
    GEOIP_CITY_PATH: str = "data/GeoLite2-City.mmdb"
    GEOIP_ASN_PATH: str = "data/GeoLite2-ASN.mmdb"
    TOR_EXIT_NODES_PATH: str = "data/tor_exit_nodes.txt"

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
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

    def get_absolute_path(self, relative_path: str) -> Path:
        """Resolve a path relative to the backend root directory."""
        p = Path(relative_path)
        if p.is_absolute():
            return p
        return BASE_DIR / relative_path

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
