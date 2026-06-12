"""Подготовка данных разведки для LLM-аудита."""

from __future__ import annotations

from typing import Any, Dict, List, Set
from urllib.parse import urlparse


def format_recon_for_llm(recon_data: Dict[str, Any], *, max_items: int = 8) -> str:
    """Компактный текстовый блок OSINT для промпта LLM."""
    if not recon_data:
        return ""

    lines: List[str] = ["=== Данные разведки (OSINT) ==="]

    target = recon_data.get("target")
    if target:
        lines.append(f"Цель разведки: {target}")

    summary = recon_data.get("summary")
    if summary:
        lines.append(f"Сводка recon: {summary}")

    hosts = recon_data.get("subdomains", {}).get("hosts", [])
    if hosts:
        lines.append(f"Поддомены ({len(hosts)}): " + ", ".join(hosts[:max_items]))
        if len(hosts) > max_items:
            lines.append(f"  ... и ещё {len(hosts) - max_items}")

    ips = recon_data.get("resolved_ips", [])
    if ips:
        lines.append("IP: " + ", ".join(ips[:max_items]))

    subnets = recon_data.get("subnets", [])
    if subnets:
        lines.append("Подсети: " + ", ".join(subnets[:max_items]))

    tech = recon_data.get("technologies", {}).get("technologies", [])
    if tech:
        lines.append("Технологии: " + "; ".join(tech[:max_items]))

    for item in recon_data.get("files", {}).get("found", [])[:max_items]:
        snippet = (item.get("snippet") or "")[:120]
        lines.append(f"Файл [{item.get('status')}]: {item.get('url')} — {snippet}")

    for item in recon_data.get("github_leaks", {}).get("snippets", [])[:max_items]:
        lines.append(
            f"GitHub: {item.get('repository')}/{item.get('path')} — {item.get('url')}"
        )

    seo = recon_data.get("seo", {})
    robots_paths = seo.get("robots_txt", {}).get("paths", [])
    if robots_paths:
        lines.append("robots.txt пути: " + ", ".join(robots_paths[:10]))

    ti = recon_data.get("threat_intel", {})
    if ti.get("cves"):
        lines.append("CVE из TI: " + ", ".join(ti["cves"][:10]))
    for finding in ti.get("findings", [])[:max_items]:
        lines.append(f"TI [{finding.get('type')}]: {finding}")

    dorks = recon_data.get("dorks", {})
    for hit in dorks.get("google_dorks", {}).get("results", [])[:max_items]:
        lines.append(f"Google dork: {hit.get('title')} — {hit.get('url')}")
    for block in dorks.get("shodan_dorks", {}).get("by_query", [])[:3]:
        for match in block.get("matches", [])[:3]:
            lines.append(
                f"Shodan dork [{block.get('query')}]: {match.get('ip')}:{match.get('port')}"
            )

    shodan_matches = recon_data.get("shodan_search", {}).get("matches", [])
    if shodan_matches:
        lines.append("Shodan exposed:")
        for match in shodan_matches[:5]:
            lines.append(
                f"  {match.get('ip')}:{match.get('port')} — {match.get('product') or match.get('service')}"
            )

    return "\n".join(lines)


def extract_crawl_seeds(recon_data: Dict[str, Any], base_url: str, *, max_urls: int = 8) -> List[str]:
    """URL для приоритетного краула на основе recon."""
    seeds: List[str] = []
    seen: Set[str] = set()

    def add(url: str) -> None:
        if not url or url in seen:
            return
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        seen.add(url)
        seeds.append(url)

    add(base_url)

    for host in recon_data.get("subdomains", {}).get("hosts", [])[:max_urls]:
        add(f"https://{host}")

    for item in recon_data.get("files", {}).get("found", []):
        if item.get("status") == 200 and item.get("url"):
            add(item["url"])

    for url in recon_data.get("seo", {}).get("sitemap", {}).get("urls", []):
        add(url)

    return seeds[:max_urls]


def extract_allowed_domains(recon_data: Dict[str, Any], base_url: str) -> Set[str]:
    """Разрешённые домены для краула (корень + поддомены)."""
    domains: Set[str] = set()
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    if parsed.netloc:
        root = parsed.netloc.lower()
        domains.add(root)
        parts = root.split(".")
        if len(parts) >= 2:
            domains.add(".".join(parts[-2:]))

    for host in recon_data.get("subdomains", {}).get("hosts", []):
        domains.add(host.lower())

    return domains


def build_attack_surface(recon_data: Dict[str, Any]) -> Dict[str, Any]:
    """Структурированная поверхность атаки для PromptContext."""
    return {
        "subdomains_count": recon_data.get("subdomains", {}).get("count", 0),
        "ips": recon_data.get("resolved_ips", [])[:20],
        "subnets": recon_data.get("subnets", [])[:10],
        "technologies": recon_data.get("technologies", {}).get("technologies", [])[:15],
        "exposed_files": [
            item.get("url")
            for item in recon_data.get("files", {}).get("found", [])
            if item.get("status") == 200
        ][:10],
        "github_leaks": len(recon_data.get("github_leaks", {}).get("snippets", [])),
        "threat_score": recon_data.get("threat_intel", {}).get("risk_score", 0),
    }
