"""Генерация отчётов по результатам разведки."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict


def build_text_summary(data: Dict[str, Any]) -> str:
    parts: list[str] = []
    subs = data.get("subdomains", {})
    if subs.get("count"):
        parts.append(f"поддоменов: {subs['count']}")
    ips = data.get("resolved_ips", [])
    if ips:
        parts.append(f"IP: {len(ips)}")
    subnets = data.get("subnets", [])
    if subnets:
        parts.append(f"подсетей: {len(subnets)}")
    tech = data.get("technologies", {}).get("technologies", [])
    if tech:
        parts.append(f"технологий: {len(tech)}")
    files = data.get("files", {}).get("count", 0)
    if files:
        parts.append(f"файлов: {files}")
    leaks = data.get("github_leaks", {}).get("count", 0)
    if leaks:
        parts.append(f"GitHub-утечек: {leaks}")
    dork_hits = data.get("dorks", {}).get("total_hits", 0)
    if dork_hits:
        parts.append(f"dork-хитов: {dork_hits}")
    ti = data.get("threat_intel", {})
    if ti.get("findings_count"):
        parts.append(f"TI-находок: {ti['findings_count']}")
    return ". ".join(parts) if parts else "Разведка выполнена."


def build_action_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    defensive: list[str] = []
    offensive: list[str] = []

    if data.get("subdomains", {}).get("count", 0) > 5:
        defensive.append("Проверьте все обнаруженные поддомены и отключите неиспользуемые.")
    if data.get("files", {}).get("count", 0):
        defensive.append("Удалите или закройте доступ к обнаруженным чувствительным файлам.")
    if data.get("github_leaks", {}).get("count", 0):
        defensive.append("Ротируйте секреты, найденные в публичных репозиториях GitHub.")
    for cve in data.get("threat_intel", {}).get("cves", [])[:5]:
        defensive.append(f"Проверьте и пропатчите уязвимость {cve}.")

    if data.get("shodan_search", {}).get("total"):
        offensive.append("Используйте Shodan-dork для мониторинга новых exposed-сервисов.")
    if data.get("subnets"):
        offensive.append("Просканируйте обнаруженные подсети в рамках согласованного scope.")

    return {
        "changes": build_text_summary(data),
        "defensive_actions": defensive or ["Продолжайте мониторинг инфраструктуры."],
        "offensive_actions": offensive or ["Запланируйте повторную разведку после исправлений."],
    }


def build_markdown_report(
    target: str,
    target_type: str,
    data: Dict[str, Any],
    *,
    event_id: str | None = None,
) -> str:
    lines = [
        f"# Отчёт разведки: {target}",
        "",
        f"- **Тип цели:** {target_type}",
        f"- **Дата:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    if event_id:
        lines.append(f"- **ID:** `{event_id}`")
    lines.extend(["", "## Сводка", "", build_text_summary(data), ""])

    subs = data.get("subdomains", {}).get("hosts", [])
    if subs:
        lines.extend(["## Поддомены", ""])
        for host in subs[:50]:
            lines.append(f"- `{host}`")
        if len(subs) > 50:
            lines.append(f"- ... и ещё {len(subs) - 50}")
        lines.append("")

    ips = data.get("resolved_ips", [])
    if ips:
        lines.extend(["## IP-адреса", ""])
        for ip in ips:
            lines.append(f"- `{ip}`")
        lines.append("")

    subnets = data.get("subnets", [])
    if subnets:
        lines.extend(["## Подсети", ""])
        for net in subnets:
            lines.append(f"- `{net}`")
        lines.append("")

    tech = data.get("technologies", {}).get("technologies", [])
    if tech:
        lines.extend(["## Технологии", ""])
        for t in tech:
            lines.append(f"- {t}")
        lines.append("")

    files = data.get("files", {}).get("found", [])
    by_host = data.get("files", {}).get("by_host", {})
    if files:
        lines.extend(["## Обнаруженные файлы", ""])
        if by_host:
            for host, items in by_host.items():
                lines.append(f"### `{host}`")
                for f in items:
                    lines.append(f"- [{f.get('status')}] {f.get('url')}")
        else:
            for f in files:
                lines.append(f"- [{f.get('status')}] {f.get('url')}")
        lines.append("")

    dorks = data.get("dorks", {})
    google = dorks.get("google_dorks", {})
    if google.get("results"):
        lines.extend([f"## Google dorks ({google.get('engine', 'n/a')})", ""])
        for hit in google["results"][:25]:
            lines.append(f"- **{hit.get('title', 'result')}** — {hit.get('url')}")
            if hit.get("snippet"):
                lines.append(f"  > {hit.get('snippet')[:200]}")
        lines.append("")

    shodan_dorks = dorks.get("shodan_dorks", {})
    if shodan_dorks.get("by_query"):
        lines.extend(["## Shodan dorks", ""])
        for block in shodan_dorks["by_query"][:10]:
            lines.append(f"### `{block.get('query')}`")
            for match in block.get("matches", [])[:8]:
                lines.append(
                    f"- {match.get('ip')}:{match.get('port')} — {match.get('product') or match.get('service')}"
                )
        lines.append("")

    leaks = data.get("github_leaks", {}).get("snippets", [])
    if leaks:
        lines.extend(["## GitHub (утечки кода)", ""])
        for s in leaks:
            lines.append(f"- `{s.get('repository')}/{s.get('path')}` — {s.get('url')}")
        lines.append("")

    ti = data.get("threat_intel", {})
    if ti.get("findings"):
        lines.extend([f"## Threat Intelligence (score: {ti.get('risk_score', 0)})", ""])
        for f in ti["findings"][:20]:
            lines.append(f"- [{f.get('type')}] {f}")
        lines.append("")

    actions = data.get("action_summary", {})
    if actions:
        lines.extend(["## Рекомендации", ""])
        for item in actions.get("defensive_actions", []):
            lines.append(f"- 🛡 {item}")
        for item in actions.get("offensive_actions", []):
            lines.append(f"- ⚔ {item}")
        lines.append("")

    return "\n".join(lines)
