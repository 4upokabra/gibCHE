from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol

import httpx
from playwright.async_api import Browser, async_playwright

from .models import PageContent, PageRequest

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


class FetchError(Exception):
    pass


class AsyncFetcher(Protocol):
    async def fetch(self, request: PageRequest) -> PageContent: ...

    async def aclose(self) -> None: ...


@dataclass
class RequestsFetcher:
    timeout: int = 20
    follow_redirects: bool = True
    _client: Optional[httpx.AsyncClient] = None

    async def fetch(self, request: PageRequest) -> PageContent:
        if not self._client:
            self._client = httpx.AsyncClient(
                timeout=request.timeout or self.timeout,
                follow_redirects=self.follow_redirects,
                headers={**DEFAULT_HEADERS, **(request.headers or {})},
            )
        client = self._client
        try:
            response = await client.get(
                request.url,
                headers=self._merge_headers(request),
                timeout=request.timeout or self.timeout,
            )
        except httpx.HTTPError as exc:
            raise FetchError(str(exc)) from exc

        fetched_at = datetime.now(timezone.utc)
        if not response.text:
            raise FetchError(f"Empty response body for {request.url}")

        return PageContent(
            url=str(response.url),
            status=response.status_code,
            raw_html=response.text,
            fetched_at=fetched_at,
            transport="requests",
            metadata={
                "final_url": str(response.url),
                "status": response.status_code,
                "headers": dict(response.headers),
                "request_headers": self._merge_headers(request),
                "elapsed": response.elapsed.total_seconds(),
            },
        )

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _merge_headers(self, request: PageRequest) -> Dict[str, str]:
        headers = {**DEFAULT_HEADERS, **(request.headers or {})}
        if request.user_agent:
            headers["User-Agent"] = request.user_agent
        return headers


class PlaywrightFetcher:
    def __init__(
        self,
        browser_type: str = "chromium",
        headless: bool = True,
        proxy: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.browser_type = browser_type
        self.headless = headless
        self.proxy = proxy

        self._playwright = None
        self._browser: Optional[Browser] = None
        self._lock = asyncio.Lock()

    async def fetch(self, request: PageRequest) -> PageContent:
        await self._ensure_browser()
        assert self._browser is not None

        context = await self._browser.new_context(
            user_agent=request.user_agent,
            extra_http_headers=request.headers,
            timezone_id="UTC",
        )
        page = await context.new_page()
        try:
            response = await page.goto(
                request.url,
                wait_until="domcontentloaded",
                timeout=(request.timeout or 20) * 1000,
            )
            await page.wait_for_timeout(1000)
            content = await page.content()
            status = response.status if response else 0
            fetched_at = datetime.now(timezone.utc)
            screenshot_bytes = await page.screenshot(type="png")
            return PageContent(
                url=page.url,
                status=status,
                raw_html=content,
                fetched_at=fetched_at,
                transport="playwright",
                metadata={
                    "final_url": page.url,
                    "request_headers": request.headers or {},
                    "snapshot_base64": base64.b64encode(screenshot_bytes).decode("ascii"),
                },
            )
        except Exception as exc:  # noqa: BLE001
            raise FetchError(str(exc)) from exc
        finally:
            await context.close()

    async def aclose(self) -> None:
        async with self._lock:
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None

    async def _ensure_browser(self) -> None:
        async with self._lock:
            if self._browser:
                return
            self._playwright = await async_playwright().start()
            browser_factory = getattr(self._playwright, self.browser_type)
            self._browser = await browser_factory.launch(
                headless=self.headless,
                proxy=self.proxy,
            )


