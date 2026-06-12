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
    gh = data.get("github_leaks", {})
    leaks = gh.get("count") or len(gh.get("snippets") or [])
    if leaks:
        parts.append(f"GitHub-утечек: {leaks}")
    dork_hits = data.get("dorks", {}).get("total_hits", 0)
    if dork_hits:
        parts.append(f"dork-хитов: {dork_hits}")
    ti = data.get("threat_intel", {})
    if ti.get("findings_count"):
        parts.append(f"TI-находок: {ti['findings_count']}")
    return ". ".join(parts) if parts else "Разведка выполнена."


def _collect_open_ports(data: Dict[str, Any]) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    network = data.get("network_scan", {})
    hosts = network.get("hosts", {}) if isinstance(network, dict) else {}
    for host_info in hosts.values():
        if not isinstance(host_info, dict):
            continue
        for port_info in host_info.get("ports", []) or []:
            if str(port_info.get("state", "")).lower() not in {"open", "open|filtered"}:
                continue
            ports.append(port_info)
    return ports


def _collect_technologies(data: Dict[str, Any]) -> list[str]:
    tech_block = data.get("technologies", {})
    if isinstance(tech_block, dict):
        return [str(t) for t in tech_block.get("technologies", []) if t]
    return []


def _stack_flags(technologies: list[str]) -> Dict[str, bool]:
    blob = " ".join(technologies).lower()
    return {
        "php": "php" in blob,
        "asp": "asp.net" in blob,
        "iis": "iis" in blob or "microsoft-iis" in blob,
        "tomcat": "tomcat" in blob or "coyote" in blob,
        "apache": "apache" in blob,
    }


def _exposed_files(files: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    exposed: list[Dict[str, Any]] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        try:
            status = int(item.get("status") or 0)
        except (TypeError, ValueError):
            continue
        if 200 <= status < 300:
            exposed.append(item)
    return exposed


def _append_unique(bucket: list[str], message: str) -> None:
    if message and message not in bucket:
        bucket.append(message)


def build_action_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    """Контекстные рекомендации по фактам разведки."""
    defensive: list[str] = []
    offensive: list[str] = []
    target = str(data.get("target") or "цели")
    technologies = _collect_technologies(data)
    stack = _stack_flags(technologies)
    tech_line = "; ".join(technologies[:3]) if technologies else "не определён"

    sub_count = data.get("subdomains", {}).get("count", 0)
    if sub_count > 5:
        _append_unique(
            defensive,
            f"Обнаружено {sub_count} поддоменов — инвентаризируйте и отключите неиспользуемые DNS-записи.",
        )

    open_ports = _collect_open_ports(data)
    network_scan = data.get("network_scan", {})
    nmap_ran = isinstance(network_scan, dict) and network_scan.get("source") == "nmap"
    nmap_empty = nmap_ran and not network_scan.get("hosts")
    scan_thin = not open_ports and not technologies
    http_ports = sorted(
        {str(p.get("port")) for p in open_ports if str(p.get("service", "")).lower() == "http"}
    )
    if http_ports:
        if len(http_ports) > 1:
            _append_unique(
                defensive,
                f"Снаружи открыто несколько HTTP-портов ({', '.join(http_ports)}) — оставьте только нужный.",
            )
        else:
            _append_unique(
                defensive,
                f"Порт {http_ports[0]}/tcp (HTTP) доступен извне — ограничьте доступ firewall при необходимости.",
            )

    seo_title = (data.get("seo", {}).get("meta") or {}).get("title", "")
    is_rest_api = "rest" in target.lower() or "api" in seo_title.lower()

    if stack["php"]:
        _append_unique(
            defensive,
            f"Стек {tech_line}: PHP устарел — обновите версию и скройте заголовок X-Powered-By.",
        )
        if is_rest_api:
            _append_unique(
                offensive,
                f"Проверьте REST API {target}: IDOR, broken auth, mass assignment, injection в параметрах.",
            )
        else:
            _append_unique(
                offensive,
                f"Проверьте PHP-приложение {target} на SQLi/XSS через LLM-аудит.",
            )
    elif stack["iis"] or stack["asp"]:
        _append_unique(defensive, "Стек IIS/ASP.NET — обновите компоненты и отключите раскрытие версий.")
        _append_unique(offensive, f"Проверьте ASP.NET-формы и ViewState на {target}.")
    elif stack["tomcat"]:
        _append_unique(defensive, "Tomcat — закройте /manager и /host-manager, если они доступны.")
        _append_unique(offensive, f"Проверьте Java endpoints и админ-консоли на {target}.")
    elif stack["apache"]:
        _append_unique(defensive, f"Apache ({tech_line}) — скройте точную версию в заголовке Server.")

    all_files = data.get("files", {}).get("found", [])
    exposed = _exposed_files(all_files)
    blocked = [f for f in all_files if f not in exposed]
    if exposed:
        urls = ", ".join(f.get("url", "") for f in exposed[:3])
        _append_unique(defensive, f"Публично доступные пути: {urls} — закройте или уберите чувствительное.")
    for item in blocked[:2]:
        url = item.get("url", "")
        if "server-status" in url:
            _append_unique(
                defensive,
                f"{url} отвечает {item.get('status')} — убедитесь, что mod_status недоступен анонимно.",
            )

    for host_entry in data.get("shodan_hosts", [])[:1]:
        if not isinstance(host_entry, dict):
            continue
        shodan_data = host_entry.get("data", {})
        vulns = shodan_data.get("vulnerabilities") or []
        if vulns:
            ip = host_entry.get("ip", "")
            _append_unique(
                defensive,
                f"Shodan связывает хост {ip} с {len(vulns)} известными CVE для стека — "
                f"планируйте обновление ({tech_line}), не патчите по списку вслепую.",
            )

    ti = data.get("threat_intel", {})
    for finding in ti.get("findings", [])[:3]:
        if not isinstance(finding, dict):
            continue
        if finding.get("type") == "exposed_file" and finding.get("url", "").endswith("robots.txt"):
            continue
        _append_unique(
            defensive,
            f"TI [{finding.get('type')}]: {finding.get('url') or 'см. отчёт'}.",
        )

    leak_count = data.get("github_leaks", {}).get("count", 0)
    if leak_count:
        _append_unique(
            defensive,
            f"GitHub: найдено {leak_count} потенциальных утечек — ротируйте секреты.",
        )

    vt_stats = (
        data.get("virustotal", {})
        .get("data", {})
        .get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    if isinstance(vt_stats, dict):
        malicious = int(vt_stats.get("malicious") or 0)
        suspicious = int(vt_stats.get("suspicious") or 0)
        if malicious or suspicious:
            _append_unique(
                defensive,
                f"VirusTotal: {malicious} malicious / {suspicious} suspicious — проверьте репутацию домена.",
            )

    dork_hits = data.get("dorks", {}).get("total_hits", 0)
    if dork_hits:
        _append_unique(offensive, f"Разберите {dork_hits} попаданий dorks по {target}.")

    if scan_thin:
        if nmap_empty:
            _append_unique(
                defensive,
                f"Nmap не увидел открытых портов для {target} — хост может блокировать трафик с IP сервера сканера.",
            )
        _append_unique(
            offensive,
            f"Для поиска уязвимостей в приложении запустите LLM-аудит по прямому URL (вкладка «LLM аудит»).",
        )
    elif not offensive and http_ports:
        _append_unique(
            offensive,
            f"Запустите LLM-аудит {target} (вкладка «LLM аудит»).",
        )

    if not defensive and not scan_thin:
        _append_unique(
            defensive,
            f"Явных критичных сигналов по {target} нет — зафиксируйте baseline мониторинга.",
        )

    return {
        "changes": build_text_summary(data),
        "defensive_actions": defensive[:5],
        "offensive_actions": offensive[:4],
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
