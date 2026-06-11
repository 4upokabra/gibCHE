from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, urldefrag

from bs4 import BeautifulSoup

from .enrichment import ThreatKnowledgeBase, enrich_report
from .fetchers import AsyncFetcher, FetchError, PlaywrightFetcher, RequestsFetcher
from .llm_client import LLMClientError, OpenRouterClient
from .models import (
    LLMRequest,
    ModelProvider,
    PageContent,
    PageRequest,
    PromptContext,
    ScanReport,
    StructuredPage,
    StructuredSection,
)
from .postprocessing import PostProcessingError, build_action_summary, build_scan_report
from .processing import ProcessingOptions, build_structured_page
from .prompts import build_action_summary_messages, build_scan_messages
from .recon_context import (
    build_attack_surface,
    extract_allowed_domains,
    extract_crawl_seeds,
    format_recon_for_llm,
)


@dataclass(slots=True)
class CrawlOptions:
    max_pages: int = 5
    max_depth: int = 2
    same_domain_only: bool = True
    delay_between_requests: float = 0.0
    allowed_domains: Optional[Set[str]] = None
    seed_urls: Optional[List[str]] = None


@dataclass(slots=True)
class ScanOptions:
    model: str = "deepseek/deepseek-chat"
    provider: ModelProvider = "deepseek"
    temperature: float = 0.2
    max_output_tokens: int = 2048
    use_browser: bool = False
    crawl: CrawlOptions = field(default_factory=CrawlOptions)
    processing: ProcessingOptions = field(default_factory=ProcessingOptions)
    generate_action_summary: bool = True


class LLMScannerPipeline:
    def __init__(
        self,
        http_fetcher: Optional[AsyncFetcher] = None,
        browser_fetcher: Optional[AsyncFetcher] = None,
        llm_client: Optional[OpenRouterClient] = None,
        knowledge_base: Optional[ThreatKnowledgeBase] = None,
    ) -> None:
        self.http_fetcher = http_fetcher or RequestsFetcher()
        self.browser_fetcher = browser_fetcher or PlaywrightFetcher()
        self.llm_client = llm_client or OpenRouterClient()
        self.knowledge_base = knowledge_base or ThreatKnowledgeBase()
        self.logger = logging.getLogger(__name__)

    async def run(
        self,
        url: str,
        scan_goal: str,
        options: Optional[ScanOptions] = None,
        recon_data: Optional[Dict] = None,
    ) -> ScanReport:
        options = options or ScanOptions()
        fetcher = self.browser_fetcher if options.use_browser else self.http_fetcher

        recon_block: Optional[str] = None
        attack_surface: Optional[Dict] = None
        if recon_data:
            recon_block = format_recon_for_llm(recon_data)
            attack_surface = build_attack_surface(recon_data)
            seeds = extract_crawl_seeds(recon_data, url)
            if seeds:
                options.crawl.seed_urls = seeds
                options.crawl.max_pages = min(max(options.crawl.max_pages, len(seeds)), 10)
            options.crawl.allowed_domains = extract_allowed_domains(recon_data, url)

        page_contents, depth_map = await self._crawl_site(
            fetcher=fetcher,
            start_url=url,
            options=options,
        )
        structured_pages = [
            build_structured_page(page_content, options=options.processing)
            for page_content in page_contents
        ]
        aggregated_page = _aggregate_structured_pages(
            structured_pages=structured_pages,
            page_contents=page_contents,
            depth_map=depth_map,
            root_url=url,
        )

        prompt_context = PromptContext(
            structured_page=aggregated_page,
            scan_goal=scan_goal,
            attack_surface=attack_surface,
            recon_context=recon_block,
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
        report_metadata = dict(aggregated_page.metadata)
        if recon_data:
            report_metadata["recon_target"] = str(recon_data.get("target", ""))
            report_metadata["recon_summary"] = str(recon_data.get("summary", ""))[:500]
            if recon_data.get("threat_intel", {}).get("risk_score") is not None:
                report_metadata["recon_threat_score"] = str(
                    recon_data["threat_intel"]["risk_score"]
                )

        report = build_scan_report(
            raw_response=raw_response,
            url=page_contents[0].url if page_contents else url,
            metadata=report_metadata,
        )
        report = enrich_report(report, self.knowledge_base)

        if options.generate_action_summary:
            action_summary = await self._generate_action_summary(report, options)
            if action_summary:
                report.action_summary = action_summary

        return report

    async def aclose(self) -> None:
        await self.http_fetcher.aclose()
        await self.browser_fetcher.aclose()
        await self.llm_client.aclose()

    async def _crawl_site(
        self,
        fetcher: AsyncFetcher,
        start_url: str,
        options: ScanOptions,
    ) -> Tuple[List[PageContent], Dict[str, int]]:
        crawl_opts = options.crawl
        if crawl_opts.max_pages < 1:
            raise FetchError("crawl.max_pages must be at least 1")

        queue: deque[Tuple[str, int]] = deque([(start_url, 0)])
        if crawl_opts.seed_urls:
            for seed_url in crawl_opts.seed_urls:
                normalized_seed = _normalize_url(seed_url)
                if normalized_seed != _normalize_url(start_url):
                    queue.append((seed_url, 1))

        visited: Set[str] = set()
        results: List[PageContent] = []
        depth_map: Dict[str, int] = {}

        allowed_domains = (
            set(crawl_opts.allowed_domains)
            if crawl_opts.allowed_domains
            else {urlparse(start_url).netloc.lower()}
        )

        while queue and len(results) < crawl_opts.max_pages:
            current_url, depth = queue.popleft()
            normalized_current = _normalize_url(current_url)
            if normalized_current in visited:
                continue

            visited.add(normalized_current)
            page_request = PageRequest(url=current_url, use_browser=options.use_browser)

            try:
                page_content = await fetcher.fetch(page_request)
            except FetchError:
                continue

            final_normalized = _normalize_url(page_content.url)
            depth_map[final_normalized] = depth

            if final_normalized not in visited:
                visited.add(final_normalized)

            results.append(page_content)

            if depth >= crawl_opts.max_depth:
                continue

            links = _extract_links(page_content.raw_html, page_content.url)
            for link in links:
                normalized_link = _normalize_url(link)
                if normalized_link in visited:
                    continue
                link_domain = urlparse(normalized_link).netloc.lower()
                if crawl_opts.same_domain_only and link_domain not in allowed_domains:
                    continue
                if crawl_opts.allowed_domains and link_domain not in allowed_domains:
                    continue
                queue.append((normalized_link, depth + 1))

            if crawl_opts.delay_between_requests > 0:
                await asyncio.sleep(crawl_opts.delay_between_requests)

        if not results:
            raise FetchError(f"Не удалось загрузить страницу {start_url}")

        return results, depth_map

    async def _generate_action_summary(
        self,
        report: ScanReport,
        options: ScanOptions,
    ):
        try:
            messages = build_action_summary_messages(report)
            request = LLMRequest(
                provider=options.provider,  # type: ignore[arg-type]
                model=options.model,
                messages=messages,
                temperature=max(options.temperature, 0.1),
                max_output_tokens=min(options.max_output_tokens, 1024),
                response_format="json",
            )
            raw_response = await self.llm_client.complete(request)
            return build_action_summary(raw_response)
        except (LLMClientError, PostProcessingError, Exception) as exc:  # noqa: BLE001
            self.logger.warning("Failed to build action summary: %s", exc)
            return None


NON_HTML_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".mp4",
    ".mp3",
    ".avi",
    ".wmv",
    ".webm",
    ".mov",
    ".mkv",
    ".exe",
    ".dll",
    ".bin",
}


def _extract_links(raw_html: str, base_url: str) -> Set[str]:
    soup = BeautifulSoup(raw_html, "lxml")
    links: Set[str] = set()

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href:
            continue
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absolute_url = urljoin(base_url, href)
        cleaned_url, _ = urldefrag(absolute_url)
        normalized_url = _normalize_url(cleaned_url)
        if not normalized_url.startswith(("http://", "https://")):
            continue
        _, path_ext = _split_extension(normalized_url)
        if path_ext in NON_HTML_EXTENSIONS:
            continue
        links.add(normalized_url)

    return links


def _split_extension(url: str) -> Tuple[str, str]:
    parsed = urlsplit(url)
    path = parsed.path or ""
    if "." not in path.rsplit("/", 1)[-1]:
        return url, ""
    base, _, ext = path.rpartition(".")
    return urlunsplit((parsed.scheme, parsed.netloc, base, parsed.query, "")), f".{ext.lower()}"


def _normalize_url(url: str) -> str:
    cleaned, _ = urldefrag(url)
    split = urlsplit(cleaned)
    scheme = split.scheme.lower() or "http"
    netloc = split.netloc.lower()
    path = split.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    normalized = urlunsplit((scheme, netloc, path, split.query, ""))
    return normalized


def _aggregate_structured_pages(
    structured_pages: List[StructuredPage],
    page_contents: List[PageContent],
    depth_map: Dict[str, int],
    root_url: str,
) -> StructuredPage:
    if not structured_pages:
        return StructuredPage(
            main_text="",
            sections=[],
            metadata={"final_url": root_url, "pages_analyzed": 0, "root_url": root_url},
            tokens_estimate=0,
        )

    aggregated_sections: List[StructuredSection] = []
    main_text_parts: List[str] = []
    scope_items: List[str] = []
    total_tokens = 0

    for page_content, structured_page in zip(page_contents, structured_pages):
        normalized_url = _normalize_url(page_content.url)
        depth = depth_map.get(normalized_url, 0)
        title = structured_page.metadata.get("title") or page_content.metadata.get("title")
        page_label = title.strip() if isinstance(title, str) and title else page_content.url
        scope_items.append(f"{page_label} [{page_content.url}] depth={depth}")

        main_text_parts.append(f"[{page_label}]\n{structured_page.main_text}")
        total_tokens += structured_page.tokens_estimate

        for section in structured_page.sections:
            aggregated_sections.append(
                StructuredSection(
                    title=f"{page_label} :: {section.title}",
                    content=section.content,
                    path=[page_label, *section.path],
                    importance=max(section.importance - depth * 0.05, 0.05),
                )
            )

    metadata: Dict[str, str] = {
        "root_url": root_url,
        "final_url": page_contents[0].url,
        "pages_analyzed": str(len(page_contents)),
        "crawl_scope": "; ".join(scope_items)[:500],
    }

    return StructuredPage(
        main_text="\n\n".join(main_text_parts),
        sections=aggregated_sections,
        metadata=metadata,
        tokens_estimate=total_tokens,
    )


