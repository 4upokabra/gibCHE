from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup, Comment

from .models import PageContent, StructuredPage, StructuredSection


@dataclass(slots=True)
class ProcessingOptions:
    min_section_chars: int = 80
    max_section_chars: int = 1500
    collapse_whitespace: bool = True
    preserve_links: bool = True


WHITESPACE_RE = re.compile(r"\s+")


def build_structured_page(
    page: PageContent, options: ProcessingOptions | None = None
) -> StructuredPage:
    options = options or ProcessingOptions()
    soup, metadata = _sanitize_html(page.raw_html, options)
    sections = _extract_sections(soup, options)
    main_text = "\n\n".join(section.content for section in sections)

    metadata.setdefault("title", _extract_title(soup))
    metadata.setdefault("language", _extract_language(soup))

    tokens_estimate = _estimate_tokens(main_text)

    return StructuredPage(
        main_text=main_text,
        sections=sections,
        metadata={**page.metadata, **metadata},
        tokens_estimate=tokens_estimate,
    )


def _extract_title(soup: BeautifulSoup) -> str:
    title_tag = soup.title
    if not title_tag:
        return ""
    text = title_tag.get_text(separator=" ", strip=True)
    return text


def _extract_language(soup: BeautifulSoup) -> Optional[str]:
    html_tag = soup.html
    if not html_tag:
        return None
    lang = html_tag.get("lang") or html_tag.get("xml:lang")
    if not lang:
        return None
    return str(lang).strip() or None


def _sanitize_html(raw_html: str, options: ProcessingOptions) -> Tuple[BeautifulSoup, Dict]:
    soup = BeautifulSoup(raw_html, "lxml")
    for element in soup(["script", "style", "noscript", "iframe", "svg", "canvas"]):
        element.decompose()

    for comment in soup(text=lambda text: isinstance(text, Comment)):
        comment.extract()

    metadata = {}
    if soup.head:
        for meta in soup.head.find_all("meta"):
            name = meta.get("name") or meta.get("property")
            content = meta.get("content")
            if not name or not content:
                continue
            metadata[name.lower()] = content.strip()

    if options.collapse_whitespace:
        for text_node in soup.find_all(string=True):
            normalized = WHITESPACE_RE.sub(" ", text_node)
            text_node.replace_with(normalized.strip())

    if not options.preserve_links:
        for a_tag in soup.find_all("a"):
            a_tag.unwrap()

    return soup, metadata


def _extract_sections(
    soup: BeautifulSoup, options: ProcessingOptions
) -> List[StructuredSection]:
    sections: List[StructuredSection] = []
    hierarchy: List[str] = []

    for element in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "table"]):
        if element.name.startswith("h"):
            level = int(element.name[1])
            heading_text = element.get_text(separator=" ", strip=True)
            if not heading_text:
                continue
            hierarchy = hierarchy[: level - 1] + [heading_text]
            continue

        text = element.get_text(separator=" ", strip=True)
        if not text:
            continue

        if element.name == "table":
            headers = [
                th.get_text(separator=" ", strip=True)
                for th in element.find_all("th")
            ]
            rows = [
                [td.get_text(separator=" ", strip=True) for td in tr.find_all("td")]
                for tr in element.find_all("tr")
            ]
            table_text = _format_table(headers, rows)
            chunk = table_text
        else:
            chunk = text

        if len(chunk) < options.min_section_chars:
            continue

        sections.append(
            StructuredSection(
                title=hierarchy[-1] if hierarchy else "Content",
                content=chunk[: options.max_section_chars],
                path=hierarchy.copy(),
                importance=_score_importance(hierarchy),
            )
        )

    if not sections:
        fallback = soup.get_text(separator=" ", strip=True)
        sections.append(
            StructuredSection(
                title="Content",
                content=fallback[: options.max_section_chars],
                path=["Content"],
                importance=0.5,
            )
        )

    return sections


def _format_table(headers: List[str], rows: List[List[str]]) -> str:
    header_line = " | ".join(headers) if headers else ""
    divider = "-" * len(header_line) if header_line else ""
    row_lines = [" | ".join(row) for row in rows if any(cell for cell in row)]
    return "\n".join(line for line in [header_line, divider, *row_lines] if line)


def _score_importance(path: List[str]) -> float:
    if not path:
        return 0.3
    level = len(path)
    return max(0.1, 1.0 / level)


def _estimate_tokens(text: str) -> int:
    words = len(text.split())
    return int(words * 1.3)


