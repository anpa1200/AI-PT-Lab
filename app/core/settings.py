from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LabSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_dir: str = Field(default="data", alias="LAB_DATA_DIR")
    log_level: str = Field(default="INFO", alias="LAB_LOG_LEVEL")
    seed_on_startup: bool = Field(default=True, alias="LAB_SEED_ON_STARTUP")
    reset_on_startup: bool = Field(default=False, alias="LAB_RESET_ON_STARTUP")
    max_concurrent_sessions: int = Field(default=10, alias="LAB_MAX_CONCURRENT_SESSIONS")

    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    google_api_key: str = Field(default="", alias="GOOGLE_API_KEY")
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    vllm_base_url: str = Field(default="http://localhost:8080", alias="VLLM_BASE_URL")


settings = LabSettings()
