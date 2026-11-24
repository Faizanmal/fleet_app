"""Validated process configuration."""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = Field(validation_alias="DATABASE_URL")
    demo_auth_mode: bool = Field(default=False, validation_alias="DEMO_AUTH_MODE")
    action_mode: Literal["SANDBOX_SIMULATION"] = Field(
        default="SANDBOX_SIMULATION", validation_alias="ACTION_MODE"
    )
    separate_requester_approver: bool = Field(
        default=True, validation_alias="SEPARATE_REQUESTER_APPROVER"
    )
    model_provider: str | None = Field(default=None, validation_alias="MODEL_PROVIDER")
    model_name: str | None = Field(default=None, validation_alias="MODEL_NAME")
    tool_max_calls: int = Field(default=8, ge=1, le=100, validation_alias="TOOL_MAX_CALLS")
    tool_max_items: int = Field(default=100, ge=1, le=10000, validation_alias="TOOL_MAX_ITEMS")
    policy_version: str = Field(
        default="policy-v1", min_length=1, validation_alias="POLICY_VERSION"
    )
    app_clock: str = Field(default="UTC", validation_alias="APP_CLOCK")
    build_version: str = Field(default="dev", validation_alias="BUILD_VERSION")
    api_cors_origins: str = Field(
        default="http://localhost:3000", validation_alias="API_CORS_ORIGINS"
    )
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    app_env: str = Field(default="development", validation_alias="APP_ENV")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    @field_validator("model_provider")
    @classmethod
    def restrict_model_provider(cls, value: str | None) -> str | None:
        if value == "":
            return None
        if value is not None and value not in {"openai", "anthropic", "google"}:
            raise ValueError("MODEL_PROVIDER must be openai, anthropic, or google")
        return value

    @model_validator(mode="after")
    def reject_demo_auth_in_production(self) -> Self:
        if self.demo_auth_mode and self.app_env.casefold() in {"prod", "production"}:
            raise ValueError("DEMO_AUTH_MODE cannot be enabled in production")
        return self

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.api_cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
