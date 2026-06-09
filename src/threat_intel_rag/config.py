from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    postgres_dsn: str = Field(
        default="postgresql+asyncpg://threat_rag:threat_rag@localhost:5432/threat_rag"
    )

    redis_url: str = "redis://localhost:6379/0"
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672/"
    ollama_base_url: str = "http://localhost:11434"
    ollama_embed_model: str = "nomic-embed-text"
    ollama_llm_model: str = "llama3.1:8b-instruct"


settings = Settings()
