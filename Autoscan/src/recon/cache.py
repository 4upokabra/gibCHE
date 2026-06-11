"""Кэш результатов разведки (файловый, TTL)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_TTL_SECONDS = 3600
CACHE_DIR = Path(__file__).resolve().parents[2] / "artifacts" / "recon_cache"


def _ensure_dir() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def build_cache_key(
    target: str,
    target_type: str,
    profile: str,
    scanners: Dict[str, bool],
) -> str:
    payload = json.dumps(
        {"target": target.lower(), "type": target_type, "profile": profile, "scanners": scanners},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def get_cached(
    target: str,
    target_type: str,
    profile: str,
    scanners: Dict[str, bool],
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> Optional[Dict[str, Any]]:
    _ensure_dir()
    key = build_cache_key(target, target_type, profile, scanners)
    path = CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - record.get("cached_at", 0) > ttl_seconds:
            path.unlink(missing_ok=True)
            return None
        data = record.get("data")
        if isinstance(data, dict):
            data = dict(data)
            data["from_cache"] = True
            data["cache_key"] = key
            return data
    except (json.JSONDecodeError, OSError):
        path.unlink(missing_ok=True)
    return None


def set_cached(
    target: str,
    target_type: str,
    profile: str,
    scanners: Dict[str, bool],
    data: Dict[str, Any],
) -> str:
    _ensure_dir()
    key = build_cache_key(target, target_type, profile, scanners)
    path = CACHE_DIR / f"{key}.json"
    serializable = {k: v for k, v in data.items() if k != "from_cache"}
    record = {"cached_at": time.time(), "target": target, "data": serializable}
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return key
