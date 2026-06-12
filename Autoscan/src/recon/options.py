"""Опции пайплайна разведки."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ReconOptions:
    profile: str = "quick"  # quick | full
    use_cache: bool = True
    scanners: Dict[str, bool] = field(default_factory=lambda: {
        "nmap": True,
        "shodan": True,
        "virustotal": True,
        "subdomains": True,
        "technologies": True,
        "files": True,
        "github": True,
        "seo": True,
        "dorks": True,
    })
    overrides: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_request(
        cls,
        *,
        profile: Optional[str] = None,
        scanners: Optional[Dict[str, bool]] = None,
        overrides: Optional[Dict[str, Any]] = None,
        comprehensive: bool = False,
        use_cache: Optional[bool] = None,
    ) -> "ReconOptions":
        opts = cls()
        if use_cache is not None:
            opts.use_cache = use_cache
        if comprehensive:
            opts.profile = "full"
            opts.scanners["files"] = True
        if profile:
            opts.profile = profile
        if scanners:
            opts.scanners.update(scanners)
        if overrides:
            opts.overrides.update({k: v for k, v in overrides.items() if v})
        if opts.profile == "full":
            opts.scanners["files"] = True
        return opts

    @property
    def is_full(self) -> bool:
        return self.profile == "full"
