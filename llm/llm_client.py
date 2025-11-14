from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from .models import LLMRequest, RawLLMResponse

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class LLMClientError(Exception):
    pass


@dataclass
class OpenRouterClient:
    api_key: Optional[str] = None
    base_url: str = OPENROUTER_BASE_URL
    referer: Optional[str] = None
    site_url: Optional[str] = None
    _client: Optional[httpx.AsyncClient] = None

    async def complete(self, request: LLMRequest) -> RawLLMResponse:
        client = await self._ensure_client()
        payload = self._build_payload(request)
        headers = self._build_headers()

        try:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=60,
            )
        except httpx.HTTPError as exc:  # noqa: BLE001
            raise LLMClientError(str(exc)) from exc

        if response.status_code >= 400:
            raise LLMClientError(f"OpenRouter error {response.status_code}: {response.text}")

        data = response.json()
        return RawLLMResponse(
            request=request,
            payload=data,
            received_at=datetime.now(timezone.utc),
        )

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if not self._client:
            self._client = httpx.AsyncClient(timeout=60)
        return self._client

    def _build_payload(self, request: LLMRequest) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": request.model,
            "messages": [{"role": msg.role, "content": msg.content} for msg in request.messages],
            "temperature": request.temperature,
        }
        if request.max_output_tokens:
            payload["max_tokens"] = request.max_output_tokens
        if request.response_format == "json":
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _build_headers(self) -> Dict[str, str]:
        api_key = self.api_key or os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise LLMClientError("OpenRouter API key is not configured")
        headers: Dict[str, str] = {
            "Authorization": f"Bearer {api_key}",
        }
        if self.referer:
            headers["HTTP-Referer"] = self.referer
        if self.site_url:
            headers["X-Title"] = self.site_url
        return headers


