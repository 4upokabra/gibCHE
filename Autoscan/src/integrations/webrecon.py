from __future__ import annotations

import asyncio
import re
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse

import requests


DEFAULT_XSS_PARAMS = ["q", "search", "id", "name", "query", "page", "redirect", "url"]


class XssRecon:
    """Пассивная разведка отражённого XSS: ищет параметры, чьи значения
    отражаются в ответе без экранирования."""

    provider_name = "xss_recon"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def scan(self, target: str, params: Optional[List[str]] = None) -> Dict[str, Any]:
        url = self._ensure_url(target)
        marker = f"rsx{uuid.uuid4().hex[:6]}"
        probe = f"<{marker}>"
        candidate_params = params or DEFAULT_XSS_PARAMS

        tested: List[str] = []
        reflected: List[Dict[str, Any]] = []

        for param in candidate_params:
            probe_url = self._with_query(url, {param: probe})
            tested.append(param)
            try:
                response = requests.get(probe_url, timeout=self.timeout)
            except requests.RequestException as exc:
                reflected.append({"param": param, "error": str(exc)})
                continue

            if probe in response.text:
                reflected.append(
                    {
                        "param": param,
                        "url": probe_url,
                        "status_code": response.status_code,
                        "evidence": f"Маркер '{probe}' отражён без экранирования.",
                    }
                )

        vulnerable = any("evidence" in item for item in reflected)
        return {
            "source": "xss_recon",
            "target": url,
            "marker": probe,
            "tested_params": tested,
            "reflected": reflected,
            "vulnerable": vulnerable,
        }

    @staticmethod
    def _ensure_url(target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target
        return f"http://{target}"

    @staticmethod
    def _with_query(url: str, extra: Dict[str, str]) -> str:
        parsed = urlparse(url)
        query = urlencode(extra)
        return urlunparse(parsed._replace(query=query))


class DirFuzzScanner:
    """Обнаружение скрытых директорий/файлов через gobuster (или симуляция)."""

    provider_name = "dirfuzz"
    default_wordlist = Path("data/wordlists/paths.txt")

    def __init__(self, wordlist: Optional[Path] = None):
        self.wordlist = Path(wordlist) if wordlist else self.default_wordlist
        self.gobuster_binary = shutil.which("gobuster")
        self._ensure_wordlist()

    def _ensure_wordlist(self) -> None:
        self.wordlist.parent.mkdir(parents=True, exist_ok=True)
        if not self.wordlist.exists():
            defaults = [
                "admin", "administrator", "login", "api", "backup", "config",
                "dashboard", "uploads", "static", "old", "test", "dev",
                ".git", ".env", "robots.txt", "sitemap.xml", "phpinfo.php",
                "wp-admin", "wp-login.php", "server-status",
            ]
            self.wordlist.write_text("\n".join(defaults), encoding="utf-8")

    async def scan(self, target: str, extensions: Optional[str] = None) -> Dict[str, Any]:
        url = self._ensure_url(target)
        command = [
            self.gobuster_binary or "gobuster",
            "dir",
            "-u", url,
            "-w", str(self.wordlist),
            "-q",
            "-t", "20",
        ]
        if extensions:
            command.extend(["-x", extensions])

        if not self.gobuster_binary:
            return {
                "source": "dirfuzz",
                "target": url,
                "status": "simulated",
                "command": " ".join(command),
                "found": [],
                "note": "gobuster не установлен, выполнена симуляция.",
            }

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0 and not stdout:
            return {"source": "dirfuzz", "target": url, "status": "error", "error": stderr.decode(errors="ignore")}

        found = []
        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.match(r"(\S+)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?", line)
            if match:
                found.append(
                    {
                        "path": match.group(1),
                        "status": int(match.group(2)),
                        "size": int(match.group(3)) if match.group(3) else None,
                    }
                )

        return {
            "source": "dirfuzz",
            "target": url,
            "status": "completed",
            "command": " ".join(command),
            "found": found,
        }

    @staticmethod
    def _ensure_url(target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target
        return f"http://{target}"


class NiktoScanner:
    """Быстрая проверка веб-сервера на известные мисконфигурации через nikto."""

    provider_name = "nikto"

    def __init__(self):
        self.nikto_binary = shutil.which("nikto") or shutil.which("nikto.pl")

    async def scan(self, target: str) -> Dict[str, Any]:
        url = self._ensure_url(target)
        command = [self.nikto_binary or "nikto", "-h", url, "-Tuning", "1234567890bc", "-nointeractive"]

        if not self.nikto_binary:
            return {
                "source": "nikto",
                "target": url,
                "status": "simulated",
                "command": " ".join(command),
                "findings": [],
                "note": "nikto не установлен, выполнена симуляция.",
            }

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180)
        except asyncio.TimeoutError:
            process.kill()
            return {"source": "nikto", "target": url, "status": "timeout", "command": " ".join(command), "findings": []}

        findings = []
        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("+") and "OSVDB" in line or line.startswith("+ /"):
                findings.append(line.lstrip("+ ").strip())

        return {
            "source": "nikto",
            "target": url,
            "status": "completed",
            "command": " ".join(command),
            "findings": findings[:50],
        }

    @staticmethod
    def _ensure_url(target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target
        return f"http://{target}"


__all__ = ["XssRecon", "DirFuzzScanner", "NiktoScanner"]
