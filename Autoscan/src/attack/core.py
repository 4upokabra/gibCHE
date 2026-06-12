from __future__ import annotations

import json
import logging
import os
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

import httpx

from src.core.events import BaseEvent


class AttackExecutionError(RuntimeError):
    """Базовое исключение модуля атак."""


class RecoverableAttackError(AttackExecutionError):
    """Исключение для временных ошибок (перезапуск через backoff)."""


class AttackVector(str, Enum):
    BRUTE_FORCE = "bruteforce"
    SQLI = "sqli"
    METASPLOIT = "metasploit"
    LEGACY_AUDIT = "legacy_audit"


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

        self.modules: Dict[AttackVector, BaseAttackModule] = {
            AttackVector.BRUTE_FORCE: self.brute_module,
            AttackVector.SQLI: self.sqli_module,
            AttackVector.METASPLOIT: self.meta_module,
            AttackVector.LEGACY_AUDIT: self.legacy_module,
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

