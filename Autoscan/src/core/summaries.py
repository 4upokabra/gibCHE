from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


SummaryPayload = Tuple[Optional[str], Optional[Dict[str, Any]]]


def _is_osint_recon_payload(data: Dict[str, Any]) -> bool:
    return data.get("module") == "recon" or any(
        key in data for key in ("subdomains", "technologies", "threat_intel", "dorks")
    )


def build_scan_summary(data: Any) -> SummaryPayload:
    if not isinstance(data, dict):
        return None, None

    if _is_osint_recon_payload(data):
        from src.recon.reporting import build_action_summary, build_text_summary

        text = build_text_summary(data)
        network = data.get("network_scan", {})
        hosts = network.get("hosts", {}) if isinstance(network, dict) else {}
        if hosts:
            open_ports = _count_open_ports(hosts)
            text = f"Nmap: {len(hosts)} хостов, {open_ports} открытых портов. {text}"
        return text, build_action_summary(data)

    summary_parts: List[str] = []
    defensive: List[str] = []
    offensive: List[str] = []

    def handle_nmap(block: Dict[str, Any], label: str = "Nmap") -> None:
        hosts = block.get("hosts")
        if isinstance(hosts, dict) and hosts:
            host_count = len(hosts)
            open_ports = _count_open_ports(hosts)
            summary_parts.append(f"{label}: {host_count} хостов, {open_ports} открытых портов.")
            defensive.append("Проверьте сервисы и закройте лишние порты, найденные сканером.")

    # прямые отчёты Nmap
    if "hosts" in data:
        handle_nmap(data)

    for key in ("network_scan", "network_discovery", "dns_info", "data"):
        block = data.get(key)
        if isinstance(block, dict) and "hosts" in block:
            handle_nmap(block, f"{key}")

    shodan_data = _extract_shodan_data(data)
    if shodan_data:
        summary_parts.append(shodan_data["summary"])
        defensive.extend(shodan_data["defensive"])

    vt_data = _extract_vt_data(data)
    if vt_data:
        summary_parts.append(vt_data["summary"])
        defensive.extend(vt_data["defensive"])

    if not summary_parts:
        summary_parts.append("Сканирование завершено, подробности в отчёте.")

    if not offensive:
        offensive.append("Сверьте отчёт с baseline и запланируйте точечную проверку найденных сервисов.")

    action_summary = {
        "changes": "Сканирование выполнено",
        "defensive_actions": defensive,
        "offensive_actions": offensive,
    }

    return " ".join(summary_parts), action_summary


def build_attack_summary(data: Any) -> SummaryPayload:
    if not isinstance(data, dict):
        return None, None

    target = data.get("target", "неизвестная цель")
    vector = data.get("vector", "атака")
    status = data.get("status", "completed")
    success = bool(data.get("success", status == "completed"))

    summary = f"Атака {vector} на {target} завершилась статусом {status}."
    details = data.get("details")

    defensive: List[str] = []
    offensive: List[str] = []

    matched = data.get("matched_vulns") or []
    if matched:
        defensive.append(f"Проверьте {len(matched)} совпадений со старыми уязвимостями и устраните их.")

    artifacts = data.get("artifacts") or {}
    if isinstance(artifacts, dict):
        command = artifacts.get("command")
        if command:
            offensive.append(f"Команда запуска сохранена в артефактах: `{command[:80]}...`")
        auto = artifacts.get("auto_exploits")
        if isinstance(auto, list) and auto:
            offensive.append(f"Автозапуск эксплойтов: {len(auto)} попыток, проверьте их статус.")

    if success:
        defensive.append("Проведите пост-инцидентный анализ и обновите контроль доступа.")
        offensive.append("Используйте полученные артефакты в безопасной среде для дальнейших проверок.")
    else:
        offensive.append("Повторите атаку после корректировки параметров или профиля.")

    action_summary = {
        "changes": details or "",
        "defensive_actions": defensive,
        "offensive_actions": offensive,
    }

    return summary, action_summary


def _count_open_ports(hosts: Dict[str, Any]) -> int:
    total = 0
    for info in hosts.values():
        ports = info.get("ports")
        if isinstance(ports, list):
            total += sum(
                1 for port in ports if str(port.get("state", "")).lower() in {"open", "open|filtered"}
            )
    return total


def _extract_shodan_data(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    shodan_section = data.get("shodan")
    if not isinstance(shodan_section, dict):
        return None
    payload = shodan_section.get("data") if isinstance(shodan_section.get("data"), dict) else shodan_section
    if not isinstance(payload, dict):
        return None

    ports = payload.get("ports") or []
    vulns = payload.get("vulnerabilities") or []
    services = payload.get("services") or []

    summary_parts = []
    defensive: List[str] = []

    if ports:
        summary_parts.append(f"Shodan: {len(ports)} открытых портов.")
        defensive.append("Ограничьте доступ к портам, обнаруженным Shodan.")
    if vulns:
        summary_parts.append(f"Shodan: {len(vulns)} потенциальных уязвимостей.")
        defensive.append("Сверьтесь со списком уязвимостей Shodan и обновите ПО.")
    if services and not summary_parts:
        summary_parts.append(f"Shodan: обнаружено {len(services)} сервисов.")

    if not summary_parts:
        return None

    return {"summary": " ".join(summary_parts), "defensive": defensive}


def _extract_vt_data(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    vt_section = data.get("virustotal")
    if not isinstance(vt_section, dict):
        return None
    payload = vt_section.get("data")
    if not isinstance(payload, dict):
        return None

    attributes = payload.get("data")
    if isinstance(attributes, dict):
        attributes = attributes.get("attributes", {})
    if not isinstance(attributes, dict):
        attributes = payload.get("attributes", {})

    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None

    malicious = stats.get("malicious") or 0
    suspicious = stats.get("suspicious") or 0
    harmless = stats.get("harmless") or 0

    summary = f"VirusTotal: {malicious} malicious / {suspicious} suspicious / {harmless} harmless детектов."
    defensive = ["Изучите отчёт VirusTotal и блокируйте отмеченные IOC."]

    return {"summary": summary, "defensive": defensive}


__all__ = ["build_scan_summary", "build_attack_summary"]


