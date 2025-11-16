from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import (
    ActionSummary,
    LLMMessage,
    LLMRequest,
    RawLLMResponse,
    ScanFinding,
    ScanReport,
)

SEVERITY_ORDER = {"critical", "high", "medium", "low", "info"}


class PostProcessingError(Exception):
    pass


def build_scan_report(
    raw_response: RawLLMResponse,
    url: str,
    metadata: Dict[str, Any] | None = None,
) -> ScanReport:
    payload = _extract_payload(raw_response)
    summary = payload.get("summary", "").strip()
    findings = [_build_finding(item) for item in payload.get("findings", [])]
    taxonomy = _build_taxonomy(findings)
    cvss = _compute_cvss_rating(findings)
    metadata = metadata or {}
    metadata.update(
        {
            "risk_rating": payload.get("risk_rating"),
            "notes": payload.get("notes", []),
            "taxonomy": taxonomy,
            "cvss": cvss,
        }
    )
    summary_blocks = [summary] if summary else []
    if cvss:
        summary_blocks.append(
            f"Оценка риска (CVSS v3.1): {cvss['score']} ({cvss['label']}). "
            f"Наиболее критичное обнаружение: {cvss['source']}."
        )
    if taxonomy["cwe"] or taxonomy["bdu"] or taxonomy["threats"]:
        taxonomy_lines = []
        if taxonomy["cwe"]:
            taxonomy_lines.append(f"CWE: {', '.join(taxonomy['cwe'][:8])}")
        if taxonomy["bdu"]:
            taxonomy_lines.append(f"БДУ ФСТЭК: {', '.join(taxonomy['bdu'][:8])}")
        if taxonomy["threats"]:
            taxonomy_lines.append(f"УБИ: {', '.join(taxonomy['threats'][:8])}")
        block = "Классификация: " + " | ".join(taxonomy_lines)
        summary_blocks.append(block)
    summary = "\n\n".join(summary_blocks)
    return ScanReport(
        url=url,
        fetched_at=raw_response.received_at,
        summary=summary,
        findings=findings,
        raw_response=raw_response,
        metadata=metadata,
    )


def _extract_payload(raw_response: RawLLMResponse) -> Dict[str, Any]:
    choices = raw_response.payload.get("choices")
    if not choices:
        raise PostProcessingError("LLM response did not contain choices")
    content = choices[0].get("message", {}).get("content", "").strip()
    if not content:
        raise PostProcessingError("LLM response content is empty")
    content = _strip_code_fence(content)
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        fragment = _extract_json_fragment(content)
        if fragment is None:
            raise PostProcessingError(f"Failed to parse JSON: {exc}") from exc
        return fragment


def _build_finding(item: Dict[str, Any]) -> ScanFinding:
    severity = _normalize_severity(item.get("severity", "info"))
    evidence = _as_list(item.get("evidence"))
    recommendations = _as_list(item.get("recommendations"))
    return ScanFinding(
        title=item.get("title", "Unnamed finding"),
        severity=severity,
        description=item.get("description", ""),
        evidence=evidence,
        recommendations=recommendations,
        cwe_ids=_as_list(item.get("cwe_ids")),
        cve_ids=_as_list(item.get("cve_ids")),
        bdu_ids=_as_list(item.get("bdu_ids")),
        threat_ids=_as_list(item.get("threat_ids")),
        likelihood=item.get("likelihood"),
        impact=item.get("impact"),
    )


def _build_taxonomy(findings: List[ScanFinding]) -> Dict[str, List[str]]:
    cwe_ids: List[str] = []
    bdu_ids: List[str] = []
    threat_ids: List[str] = []
    for finding in findings:
        cwe_ids.extend(finding.cwe_ids or [])
        bdu_ids.extend(finding.bdu_ids or [])
        threat_ids.extend(finding.threat_ids or [])

    def _unique(values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            value = value.strip()
            if not value or value in seen:
                continue
            seen.add(value)
            ordered.append(value)
        return ordered

    return {
        "cwe": _unique(cwe_ids),
        "bdu": _unique(bdu_ids),
        "threats": _unique(threat_ids),
    }


def _compute_cvss_rating(findings: List[ScanFinding]) -> Dict[str, Any] | None:
    if not findings:
        return None

    severity_map = {
        "critical": 9.5,
        "high": 8.5,
        "medium": 6.0,
        "low": 3.0,
        "info": 0.1,
    }
    label_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }

    best_finding: ScanFinding | None = None
    best_score = -1.0

    for finding in findings:
        score = severity_map.get(finding.severity or "info")
        if score is None:
            continue
        if score > best_score:
            best_score = score
            best_finding = finding

    if best_finding is None:
        return None

    best_severity = best_finding.severity or "info"
    label = label_map.get(best_severity, "Informational")

    return {
        "score": round(best_score, 1),
        "label": label,
        "source": best_finding.title,
    }


def build_action_summary(raw_response: RawLLMResponse) -> ActionSummary:
    payload = _extract_payload(raw_response)
    changes = payload.get("changes", "").strip()
    defensive_actions = _as_list(payload.get("defensive_actions"))
    offensive_actions = _as_list(payload.get("offensive_actions"))
    return ActionSummary(
        changes=changes,
        defensive_actions=defensive_actions,
        offensive_actions=offensive_actions,
    )


def _normalize_severity(value: str) -> str:
    value = (value or "").lower()
    if value not in SEVERITY_ORDER:
        return "info"
    return value


def _as_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def serialize_action_summary(action_summary: ActionSummary | None) -> Optional[Dict[str, Any]]:
    if not action_summary:
        return None
    return {
        "changes": action_summary.changes,
        "defensive_actions": list(action_summary.defensive_actions or []),
        "offensive_actions": list(action_summary.offensive_actions or []),
    }


def serialize_scan_report(report: ScanReport) -> Dict[str, Any]:
    return {
        "url": report.url,
        "fetched_at": _iso(report.fetched_at),
        "summary": report.summary,
        "findings": [_serialize_scan_finding(finding) for finding in report.findings],
        "metadata": report.metadata,
        "action_summary": serialize_action_summary(report.action_summary),
        "raw_response": _serialize_raw_response(report.raw_response),
    }


def _serialize_scan_finding(finding: ScanFinding) -> Dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity,
        "description": finding.description,
        "evidence": list(finding.evidence or []),
        "recommendations": list(finding.recommendations or []),
        "cwe_ids": list(finding.cwe_ids or []),
        "cve_ids": list(finding.cve_ids or []),
        "bdu_ids": list(finding.bdu_ids or []),
        "threat_ids": list(finding.threat_ids or []),
        "likelihood": finding.likelihood,
        "impact": finding.impact,
    }


def _serialize_raw_response(raw: RawLLMResponse) -> Dict[str, Any]:
    return {
        "received_at": _iso(raw.received_at),
        "payload": raw.payload,
        "request": _serialize_llm_request(raw.request),
    }


def _serialize_llm_request(request: LLMRequest) -> Dict[str, Any]:
    return {
        "provider": request.provider,
        "model": request.model,
        "messages": [_serialize_llm_message(msg) for msg in request.messages],
        "temperature": request.temperature,
        "max_output_tokens": request.max_output_tokens,
        "response_format": request.response_format,
    }


def _serialize_llm_message(message: LLMMessage) -> Dict[str, Any]:
    return {"role": message.role, "content": message.content}


def _iso(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    return value.isoformat()


def _strip_code_fence(content: str) -> str:
    if not content.startswith("```"):
        return content
    lines = content.splitlines()
    # Убираем первую строку с ```json или ````
    lines = lines[1:]
    while lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _extract_json_fragment(text: str) -> Any | None:
    decoder = json.JSONDecoder()
    stripped = text.strip()
    for opener in ("{", "["):
        start = stripped.find(opener)
        if start == -1:
            continue
        candidate = stripped[start:]
        try:
            obj, _ = decoder.raw_decode(candidate)
            return obj
        except json.JSONDecodeError:
            continue
    return None


__all__ = [
    "build_scan_summary",
    "build_attack_summary",
    "build_action_summary",
    "serialize_scan_report",
    "serialize_action_summary",
]


