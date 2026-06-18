from functools import lru_cache
from urllib.parse import quote_plus
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "ScamShield AI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    POSTGRES_HOST: str
    POSTGRES_PORT: int
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str

    VIRUSTOTAL_API_KEY: str
    WHOISXML_API_KEY: str

    AWS_REGION: str
    AWS_CLUSTER_NAME: str

    SANDBOX_TIMEOUT_SECONDS: int
    CACHE_TTL_HOURS: int

    @property
    def postgres_url(self) -> str:
        # URL-encode the password to safely handle special characters like '@'
        encoded_password = quote_plus(self.POSTGRES_PASSWORD)
        return f"postgresql+asyncpg://{self.POSTGRES_USER}:{encoded_password}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    @property
    def sqlite_url(self) -> str:
        return "sqlite+aiosqlite:///./scamshield.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()

