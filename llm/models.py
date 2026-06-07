from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Literal, Optional

Severity = Literal["critical", "high", "medium", "low", "info"]
Transport = Literal["requests", "playwright"]
ModelProvider = Literal["deepseek", "openai", "azure", "llama"]


@dataclass(slots=True)
class PageRequest:
    url: str
    use_browser: bool = False
    headers: Optional[Dict[str, str]] = None
    timeout: int = 20
    user_agent: Optional[str] = None


@dataclass(slots=True)
class PageContent:
    url: str
    status: int
    raw_html: str
    fetched_at: datetime
    transport: Transport
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class StructuredSection:
    title: str
    content: str
    path: List[str] = field(default_factory=list)
    importance: float = 0.0


@dataclass(slots=True)
class StructuredPage:
    main_text: str
    sections: List[StructuredSection]
    metadata: Dict[str, Any]
    tokens_estimate: int


@dataclass(slots=True)
class PromptContext:
    structured_page: StructuredPage
    scan_goal: str
    previous_findings: Optional[List["ScanFinding"]] = None
    attack_surface: Optional[Dict[str, Any]] = None
    recon_context: Optional[str] = None


@dataclass(slots=True)
class LLMMessage:
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass(slots=True)
class LLMRequest:
    provider: ModelProvider
    model: str
    messages: List[LLMMessage]
    temperature: float = 0.2
    max_output_tokens: Optional[int] = None
    response_format: Literal["json", "text"] = "json"


@dataclass(slots=True)
class RawLLMResponse:
    request: LLMRequest
    payload: Dict[str, Any]
    received_at: datetime


@dataclass(slots=True)
class ScanFinding:
    title: str
    severity: Severity
    description: str
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    bdu_ids: List[str] = field(default_factory=list)
    threat_ids: List[str] = field(default_factory=list)
    likelihood: Optional[str] = None
    impact: Optional[str] = None


@dataclass(slots=True)
class ActionSummary:
    changes: str
    defensive_actions: List[str]
    offensive_actions: List[str]


@dataclass(slots=True)
class ScanReport:
    url: str
    fetched_at: datetime
    summary: str
    findings: List[ScanFinding]
    raw_response: RawLLMResponse
    metadata: Dict[str, Any] = field(default_factory=dict)
    action_summary: Optional[ActionSummary] = None


