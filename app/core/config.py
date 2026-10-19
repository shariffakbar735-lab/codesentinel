from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    database_url: str = "postgresql+psycopg://codesentinel:codesentinel@localhost:5432/codesentinel"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    allowed_target_hosts: str = "test-api"
    allow_private_targets: bool = False
    scan_timeout_seconds: float = 5.0
    scan_max_requests: int = 50
    scan_delay_seconds: float = 0.1

    @property
    def target_allowlist(self) -> list[str]:
        return [h.strip() for h in self.allowed_target_hosts.split(",") if h.strip()]


settings = Settings()
