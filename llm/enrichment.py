from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import ScanFinding, ScanReport

DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_DATASET = DATA_DIR / "threat_catalog.json"


@dataclass(slots=True)
class ThreatRecord:
    name: str
    keywords: List[str]
    cwe_ids: List[str]
    cve_ids: List[str]
    bdu_ids: List[str]
    threat_ids: List[str]
    weight: float = 1.0

    def score(self, finding: ScanFinding) -> float:
        text = f"{finding.title} {finding.description}".lower()
        score = 0.0

        cwe_intersection = _intersect_lower(finding.cwe_ids, self.cwe_ids)
        if cwe_intersection:
            score += 5.0 * len(cwe_intersection)

        cve_intersection = _intersect_lower(finding.cve_ids, self.cve_ids)
        if cve_intersection:
            score += 4.0 * len(cve_intersection)

        for keyword in self.keywords:
            if keyword in text:
                score += 1.5

        return score * self.weight


class ThreatKnowledgeBase:
    def __init__(
        self,
        dataset_path: Optional[Path] = None,
    ) -> None:
        self.dataset_path = dataset_path or DEFAULT_DATASET
        self.records: List[ThreatRecord] = []
        self.metadata: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self.dataset_path.exists():
            with open(self.dataset_path, "r", encoding="utf-8") as file:
                data = json.load(file)
        else:
            data = {"version": "embedded", "items": []}

        self.metadata = {
            "version": str(data.get("version", "unknown")),
            "source": str(data.get("source", "manual")),
        }

        items = data.get("items", [])
        self.records = [
            ThreatRecord(
                name=item.get("name", ""),
                keywords=[keyword.lower() for keyword in item.get("keywords", [])],
                cwe_ids=_normalize_list(item.get("cwe_ids", [])),
                cve_ids=_normalize_list(item.get("cve_ids", [])),
                bdu_ids=_normalize_list(item.get("bdu_ids", [])),
                threat_ids=_normalize_list(item.get("threat_ids", [])),
                weight=float(item.get("weight", 1.0)),
            )
            for item in items
        ]

    def match_finding(self, finding: ScanFinding) -> Optional[ThreatRecord]:
        best_score = 0.0
        best_record: Optional[ThreatRecord] = None

        for record in self.records:
            score = record.score(finding)
            if score > best_score:
                best_score = score
                best_record = record

        if best_score < 1.5:
            return None
        return best_record


def enrich_report(
    report: ScanReport,
    knowledge_base: Optional[ThreatKnowledgeBase] = None,
) -> ScanReport:
    kb = knowledge_base or ThreatKnowledgeBase()
    matched = 0
    match_details: List[Dict[str, str]] = []

    for finding in report.findings:
        record = kb.match_finding(finding)
        if not record:
            continue
        matched += 1
        finding.bdu_ids = _merge_lists(finding.bdu_ids, record.bdu_ids)
        finding.cve_ids = _merge_lists(finding.cve_ids, record.cve_ids)
        finding.cwe_ids = _merge_lists(finding.cwe_ids, record.cwe_ids)
        finding.threat_ids = _merge_lists(finding.threat_ids, record.threat_ids)

        catalog_refs: List[str] = []
        if finding.bdu_ids:
            catalog_refs.append(f"БДУ: {', '.join(finding.bdu_ids)}")
        if finding.cve_ids:
            catalog_refs.append(f"CVE: {', '.join(finding.cve_ids)}")
        if finding.cwe_ids:
            catalog_refs.append(f"CWE: {', '.join(finding.cwe_ids)}")
        if finding.threat_ids:
            catalog_refs.append(f"УБИ: {', '.join(finding.threat_ids)}")

        if catalog_refs:
            note = "Связанные классификаторы: " + "; ".join(catalog_refs)
            if note not in finding.recommendations:
                finding.recommendations.append(note)

        match_details.append(
            {
                "finding_title": finding.title,
                "record_name": record.name,
                "bdu_ids": ", ".join(finding.bdu_ids),
                "cve_ids": ", ".join(finding.cve_ids),
                "cwe_ids": ", ".join(finding.cwe_ids),
                "threat_ids": ", ".join(finding.threat_ids),
            }
        )

    if matched:
        enrichment_meta = report.metadata.setdefault("enrichment", {})
        enrichment_meta["threat_catalog_version"] = kb.metadata.get("version", "unknown")
        enrichment_meta["threat_catalog_source"] = kb.metadata.get("source", "manual")
        enrichment_meta["matched_findings"] = str(matched)
        enrichment_meta["matches"] = match_details

    return report


def _normalize_list(values: Iterable[str]) -> List[str]:
    normalized: List[str] = []
    for value in values:
        if not value:
            continue
        text = str(value).strip()
        if not text:
            continue
        normalized.append(text)
    return normalized


def _merge_lists(original: Iterable[str], extra: Iterable[str]) -> List[str]:
    seen = {item for item in original if item}
    merged = [item for item in original if item]
    for item in extra:
        if not item or item in seen:
            continue
        merged.append(item)
        seen.add(item)
    return merged


def _intersect_lower(items_a: Iterable[str], items_b: Iterable[str]) -> List[str]:
    set_a = {item.lower() for item in items_a if item}
    set_b = {item.lower() for item in items_b if item}
    return sorted(set_a & set_b)

