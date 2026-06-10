from __future__ import annotations

import json
from typing import Any, Dict, List

from .models import (
    LLMMessage,
    PromptContext,
    ScanReport,
    StructuredSection,
)

SYSTEM_PROMPT = (
    "Ты — эксперт по безопасности веб-приложений. "
    "Проведи статический анализ предоставленной веб-страницы, "
    "определи потенциальные уязвимости, укажи доказательства, риск и рекомендации. "
    "Соблюдай структуру JSON-ответа."
)

RESPONSE_SCHEMA = """{
  "summary": "string",
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "description": "string",
      "evidence": ["string"],
      "recommendations": ["string"],
      "cwe_ids": ["CWE-XXX"],
      "cve_ids": ["CVE-YYYY-NNNN"],
      "bdu_ids": ["БДУ.СМ.ММ-XXX"],
      "threat_ids": ["УБИ.XXXX"],
      "likelihood": "low|medium|high",
      "impact": "low|medium|high"
    }
  ],
  "risk_rating": "low|medium|high",
  "notes": ["string"]
}"""


ACTION_SUMMARY_SCHEMA = """{
  "changes": "string",
  "defensive_actions": ["string"],
  "offensive_actions": ["string"],
  "playbook": [
    {
      "vector": "string",
      "steps": ["string"]
    }
  ]
}"""


def build_scan_messages(
    context: PromptContext,
    max_sections: int = 12,
    max_chars: int = 32_000,
) -> List[LLMMessage]:
    page = context.structured_page
    sections = _select_top_sections(page.sections, max_sections, max_chars)

    header = _format_metadata(context)
    body = "\n\n".join(_format_section(section) for section in sections)

    user_prompt = (
        f"{header}\n\n=== Содержание страницы ===\n{body}\n\n"
        "Проанализируй страницу. Ответ должен строго соответствовать JSON-схеме:\n"
        f"{RESPONSE_SCHEMA}"
    )

    return [
        LLMMessage(role="system", content=SYSTEM_PROMPT),
        LLMMessage(role="user", content=user_prompt),
    ]


def build_action_summary_messages(
    report: ScanReport,
    max_findings: int = 12,
) -> List[LLMMessage]:
    findings_lines: List[str] = []
    for finding in report.findings[:max_findings]:
        parts = [
            f"Заголовок: {finding.title}",
            f"Уровень: {finding.severity}",
            f"Описание: {finding.description}",
        ]
        if finding.recommendations:
            parts.append(
                "Рекомендации: "
                + "; ".join(rec for rec in finding.recommendations[:5])
            )
        if finding.cwe_ids:
            parts.append(f"CWE: {', '.join(finding.cwe_ids)}")
        if finding.cve_ids:
            parts.append(f"CVE: {', '.join(finding.cve_ids)}")
        if finding.bdu_ids:
            parts.append(f"БДУ: {', '.join(finding.bdu_ids)}")
        if finding.threat_ids:
            parts.append(f"УБИ: {', '.join(finding.threat_ids)}")
        findings_lines.append("\n".join(parts))

    user_prompt = (
        "Проанализируй итоги сканирования и сформируй краткое резюме изменений, "
        "а также списки приоритетных шагов защиты и возможных шагов атаки "
        "для команды Red Team. Дополнительно, если среди находок есть стандартные типы атак "
        "(SQLi, XSS, CSRF, SSRF, Path Traversal, RCE, Directory Listing, LFI/RFI и т.д.), "
        "сформируй практический мини-плейбук: упомяни вектор и 2-4 шага по реализации атаки "
        "в тестовой среде. Ответ строго в формате JSON:\n"
        f"{ACTION_SUMMARY_SCHEMA}\n\n"
        f"Общие выводы сканирования:\n{report.summary}\n\n"
        "Детали находок:\n"
        + "\n\n".join(findings_lines)
    )

    return [
        LLMMessage(
            role="system",
            content=(
                "Ты — аналитик кибербезопасности. Подготовь exec-summary для CISO, "
                "разделив рекомендации по защите и потенциальные сценарии атаки. "
                "Если есть типовые уязвимости, добавь практический плейбук атакующих действий."
            ),
        ),
        LLMMessage(role="user", content=user_prompt),
    ]


AUTO_PENTEST_PLAN_SCHEMA = """{
  "objective": "string",
  "steps": [
    {
      "id": "string",
      "kind": "audit|recon|scan|attack|report",
      "method": "llm.audit|intelligence.basic|nmap.quick|nmap.full|nmap.custom|shodan.host|virustotal.ip|attack.bruteforce|attack.sqli|attack.metasploit|json.report|llm.report",
      "args": { "key": "value" }
    }
  ]
}"""


AUTO_PENTEST_SUMMARY_SCHEMA = """{
  "summary": "string",
  "highlights": ["string"],
  "defensive_actions": ["string"],
  "offensive_actions": ["string"],
  "next_steps": ["string"]
}"""


def build_autopentest_plan_messages(target: str, profile: str, goal: str, scope: str | None, notes: str | None) -> List[LLMMessage]:
    scope_block = scope.strip() if scope else "Не указано"
    notes_block = notes.strip() if notes else "Нет дополнительных комментариев."
    schema = AUTO_PENTEST_PLAN_SCHEMA
    user_prompt = (
        "Ты — главный пентестер. Построй план Auto Pentest из 5 этапов:\n"
        "1) llm.audit — сначала проведи LLM аудит веб-приложения (Playwright/Requests).\n"
        "2) recon/scan — выбери оптимальные сканеры и аргументы (Nmap, Shodan, VirusTotal и т. д.).\n"
        "3) attack — подбери лучшие векторы (Hydra, SQLMap, Metasploit) с учётом аудита и пожеланий пользователя.\n"
        "4) report — сформируй общую JSON-сводку (json.report).\n"
        "5) llm.report — подготовь итоговый отчёт.\n\n"
        "Используй доступные инструменты:\n"
        "- intelligence.basic/comprehensive — пассивная разведка\n"
        "- nmap.* — активные сканы, можно задавать аргументы\n"
        "- shodan.host / virustotal.ip — точечные запросы\n"
        "- attack.bruteforce / attack.sqli / attack.metasploit — атаки\n"
        "- json.report, llm.report — отчётность\n\n"
        f"Профиль: {profile}. Цель: {target}. Business goal: {goal}. Scope: {scope_block}. Пожелания: {notes_block}\n"
        "План должен быть реализуем, шагов не больше 8. Ответ строго по JSON-схеме:\n"
        f"{schema}"
    )

    return [
        LLMMessage(
            role="system",
            content=(
                "Ты — Auto Pentester. Придумай план атак и разведки, используя доступные инструменты, "
                "и верни структурированный JSON."
            ),
        ),
        LLMMessage(role="user", content=user_prompt),
    ]


def build_autopentest_summary_messages(run_payload: Dict[str, Any]) -> List[LLMMessage]:
    run_json = json.dumps(run_payload, ensure_ascii=False, indent=2)
    user_prompt = (
        "Ты — ведущий пентестер. На основе журнала Auto Pentest подготовь краткое резюме работ, "
        "выдели ключевые успешные/неуспешные шаги и дай советы по защите и дальнейшим атакам. "
        "Ответ строго по JSON-схеме:\n"
        f"{AUTO_PENTEST_SUMMARY_SCHEMA}\n\n"
        "Журнал выполнения:\n"
        f"```json\n{run_json}\n```"
    )

    return [
        LLMMessage(
            role="system",
            content=(
                "Ты — эксперт по безопасности. Сформируй понятный отчёт о ходе автопентеста для CISO и Red Team."
            ),
        ),
        LLMMessage(role="user", content=user_prompt),
    ]


def _select_top_sections(
    sections: List[StructuredSection], max_sections: int, max_chars: int
) -> List[StructuredSection]:
    sorted_sections = sorted(
        sections,
        key=lambda section: section.importance,
        reverse=True,
    )
    selected: List[StructuredSection] = []
    total_chars = 0
    for section in sorted_sections:
        if len(selected) >= max_sections:
            break
        if total_chars + len(section.content) > max_chars:
            continue
        selected.append(section)
        total_chars += len(section.content)
    return selected or sections[:max_sections]


def _format_section(section: StructuredSection) -> str:
    path = " > ".join(section.path) if section.path else section.title
    return f"[{path}]\n{section.content}"


def _format_metadata(context: PromptContext) -> str:
    page = context.structured_page
    metadata = _sanitize_metadata(page.metadata)
    metadata.setdefault("scan_goal", context.scan_goal)
    if context.attack_surface:
        metadata["attack_surface"] = context.attack_surface
    if context.previous_findings:
        metadata["previous_findings_count"] = len(context.previous_findings)
    meta_lines = [f"{key}: {value}" for key, value in metadata.items() if value]
    meta_block = "\n".join(meta_lines)
    return f"URL: {metadata.get('final_url', metadata.get('url', ''))}\n{meta_block}"


IGNORED_METADATA_KEYS = {
    "snapshot_base64",
    "headers",
    "request_headers",
    "response_headers",
    "cookies",
}


def _sanitize_metadata(metadata: dict) -> dict:
    sanitized: dict = {}
    for key, value in metadata.items():
        if key in IGNORED_METADATA_KEYS:
            continue
        if value is None:
            continue
        if isinstance(value, (dict, list, set)):
            continue
        text = str(value)
        if not text or len(text) > 500:
            continue
        sanitized[key] = text
    return sanitized


