"""Structured model provider adapters for real LLM planning and reasoning."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from fleet.agent.graph import FakePlanner, Planner, ProviderPlanner
from fleet.agent.schemas import Plan
from fleet.settings import Settings, get_settings

logger = logging.getLogger(__name__)


class OpenAIStructuredProvider:
    """Invokes OpenAI (or compatible API) using structured JSON output."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def invoke_structured(
        self,
        *,
        system_prompt: str,
        payload: dict[str, Any],
        schema: type[Plan],
        temperature: float = 0.0,
    ) -> Plan | dict[str, Any]:
        schema_json = schema.model_json_schema()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        user_content = json.dumps(payload, default=str)
        body = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "fleet_plan",
                    "strict": False,
                    "schema": schema_json,
                },
            },
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=body,
                )
                response.raise_for_status()
                data = response.json()
                raw_text = data["choices"][0]["message"]["content"]
                parsed = json.loads(raw_text)
                return schema.model_validate(parsed)
        except Exception as exc:
            logger.warning("OpenAI structured invocation failed (%s)", exc)
            raise


class GeminiStructuredProvider:
    """Invokes Google Gemini using structured JSON schema output."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "gemini-1.5-flash",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def invoke_structured(
        self,
        *,
        system_prompt: str,
        payload: dict[str, Any],
        schema: type[Plan],
        temperature: float = 0.0,
    ) -> Plan | dict[str, Any]:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            f"?key={self.api_key}"
        )
        body = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": json.dumps(payload, default=str)}]}],
            "generationConfig": {
                "temperature": temperature,
                "response_mime_type": "application/json",
                "response_schema": schema.model_json_schema(),
            },
        }

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, json=body)
            response.raise_for_status()
            data = response.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(raw_text)
            return schema.model_validate(parsed)


def create_planner(settings: Settings | None = None) -> Planner:
    """Factory to create either a live ProviderPlanner or deterministic FakePlanner."""
    cfg = settings or get_settings()
    provider_type = (cfg.model_provider or "").lower().strip()

    openai_key = os.getenv("OPENAI_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")

    if (provider_type == "openai" or not provider_type) and openai_key:
        model_name = cfg.model_name or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        provider = OpenAIStructuredProvider(
            api_key=openai_key,
            model=model_name,
            base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        )
        return ProviderPlanner(provider, model_version=f"openai-{model_name}", temperature=0.0)

    if (provider_type == "google" or not provider_type) and gemini_key:
        model_name = cfg.model_name or os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        provider = GeminiStructuredProvider(api_key=gemini_key, model=model_name)
        return ProviderPlanner(provider, model_version=f"gemini-{model_name}", temperature=0.0)

    # Deterministic default for zero-cost, reproducible offline evaluation and testing
    return FakePlanner()
