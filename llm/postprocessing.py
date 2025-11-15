from __future__ import annotations

import json
from typing import Any, Dict, List

from .models import ActionSummary, RawLLMResponse, ScanFinding, ScanReport

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
    metadata = metadata or {}
    metadata.update(
        {
            "risk_rating": payload.get("risk_rating"),
            "notes": payload.get("notes", []),
        }
    )
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


