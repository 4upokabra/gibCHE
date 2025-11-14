from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .fetchers import AsyncFetcher, PlaywrightFetcher, RequestsFetcher
from .llm_client import OpenRouterClient
from .models import (
    LLMRequest,
    ModelProvider,
    PageContent,
    PageRequest,
    PromptContext,
    ScanReport,
    StructuredPage,
)
from .postprocessing import build_scan_report
from .processing import ProcessingOptions, build_structured_page
from .prompts import build_scan_messages


@dataclass(slots=True)
class ScanOptions:
    model: str = "deepseek/deepseek-chat"
    provider: ModelProvider = "deepseek"
    temperature: float = 0.2
    max_output_tokens: int = 2048
    use_browser: bool = False
    processing: ProcessingOptions = field(default_factory=ProcessingOptions)


class LLMScannerPipeline:
    def __init__(
        self,
        http_fetcher: Optional[AsyncFetcher] = None,
        browser_fetcher: Optional[AsyncFetcher] = None,
        llm_client: Optional[OpenRouterClient] = None,
    ) -> None:
        self.http_fetcher = http_fetcher or RequestsFetcher()
        self.browser_fetcher = browser_fetcher or PlaywrightFetcher()
        self.llm_client = llm_client or OpenRouterClient()

    async def run(
        self,
        url: str,
        scan_goal: str,
        options: Optional[ScanOptions] = None,
    ) -> ScanReport:
        options = options or ScanOptions()
        fetcher = self.browser_fetcher if options.use_browser else self.http_fetcher
        page_request = PageRequest(url=url, use_browser=options.use_browser)
        page_content = await fetcher.fetch(page_request)

        structured_page = build_structured_page(
            page_content, options=options.processing
        )

        prompt_context = PromptContext(
            structured_page=_merge_metadata(structured_page, page_content),
            scan_goal=scan_goal,
        )

        messages = build_scan_messages(prompt_context)
        llm_request = LLMRequest(
            provider=options.provider,  # type: ignore[arg-type]
            model=options.model,
            messages=messages,
            temperature=options.temperature,
            max_output_tokens=options.max_output_tokens,
            response_format="json",
        )
        raw_response = await self.llm_client.complete(llm_request)
        report = build_scan_report(
            raw_response=raw_response,
            url=page_content.url,
            metadata=structured_page.metadata,
        )
        return report

    async def aclose(self) -> None:
        await self.http_fetcher.aclose()
        await self.browser_fetcher.aclose()
        await self.llm_client.aclose()


def _merge_metadata(
    structured_page: StructuredPage,
    page_content: PageContent,
) -> StructuredPage:
    metadata = {**structured_page.metadata, **page_content.metadata}
    return StructuredPage(
        main_text=structured_page.main_text,
        sections=structured_page.sections,
        metadata=metadata,
        tokens_estimate=structured_page.tokens_estimate,
    )


