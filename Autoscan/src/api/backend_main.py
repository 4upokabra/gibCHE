from __future__ import annotations

import asyncio
import uuid
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from functools import partial
import os
from typing import Any, Dict, List, Optional

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from llm.pipeline import LLMScannerPipeline, ScanOptions
from llm.models import ModelProvider
from src.attack.core import AttackOrchestrator, AttackVector, TestingModel
from src.autopentest import AutoPentestOrchestrator
from src.core import crud
from src.core.database import create_tables, get_db
from src.core.summaries import build_attack_summary, build_scan_summary
from src.core.task_manager import TaskCancelledError, TaskManager
from src.integrations.nmap import NmapScanner
from src.integrations.shodan import ShodanClient
from src.integrations.virustotal import VirusTotalClient
from src.recon.enhanced_passive import EnhancedPassiveRecon


class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    NETWORK = "network"


class ScanType(str, Enum):
    QUICK = "quick"
    FULL = "full"
    VULN = "vuln"
    CUSTOM = "custom"


class AttackType(str, Enum):
    BRUTE_FORCE = AttackVector.BRUTE_FORCE.value
    SQLI = AttackVector.SQLI.value
    METASPLOIT = AttackVector.METASPLOIT.value
    LEGACY_AUDIT = AttackVector.LEGACY_AUDIT.value


class TestingProfile(str, Enum):
    BLACK = TestingModel.BLACK_BOX.value
    GREY = TestingModel.GREY_BOX.value
    WHITE = TestingModel.WHITE_BOX.value


class IntelligenceRequest(BaseModel):
    target: str
    target_type: TargetType = TargetType.IP
    comprehensive: bool = False
    label: Optional[str] = None


class ScanRequest(BaseModel):
    target: str = Field(..., description="IP, домен или сеть")
    scan_type: ScanType = ScanType.QUICK
    arguments: Optional[str] = Field(None, description="Пользовательские аргументы Nmap")
    label: Optional[str] = None


class AttackRequest(BaseModel):
    target: str
    attack_type: AttackType
    parameters: Dict[str, Any] = Field(default_factory=dict)
    profile: TestingProfile = TestingProfile.BLACK
    dry_run: bool = False
    sla: Optional[str] = None
    label: Optional[str] = None


class AttackTargetPayload(BaseModel):
    value: str
    service: Optional[str] = None
    port: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackRunRequest(BaseModel):
    attack_type: AttackType
    targets: List[AttackTargetPayload]
    profile: TestingProfile = TestingProfile.BLACK
    dry_run: bool = False
    sla: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


class AutoPentestRequest(BaseModel):
    target: str
    profile: TestingProfile = TestingProfile.BLACK
    goal: str = Field(..., description="Цель пентеста")
    scope: Optional[str] = Field(None, description="Ограничения/диапазон")
    notes: Optional[str] = Field(None, description="Комментарии и пожелания пользователя")
    label: Optional[str] = Field(None, description="Пользовательское имя задачи")


class TaskActionRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Причина управления задачей")


class BatchScanRequest(BaseModel):
    targets: List[str]
    target_type: TargetType = TargetType.IP
    label: Optional[str] = None


class LLMScanRequest(BaseModel):
    url: str = Field(..., description="Целевая страница для анализа")
    goal: str = Field(..., description="Цель сканирования/аудита")
    use_browser: bool = Field(False, description="Включить Playwright")
    model: str = Field("deepseek/deepseek-chat", description="LLM модель")
    provider: ModelProvider = Field("deepseek", description="LLM провайдер")  # type: ignore[arg-type]
    temperature: float = 0.2
    max_output_tokens: int = 2048
    metadata: Dict[str, Any] = Field(default_factory=dict)
    label: Optional[str] = None


app = FastAPI(
    title="ReconScope Backend",
    version="0.1.0",
    description="Единый backend для разведки, атак и LLM-аналитики",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

nmap_scanner = NmapScanner()
recon_engine = EnhancedPassiveRecon()
attack_orchestrator = AttackOrchestrator()
llm_pipeline = LLMScannerPipeline()
task_manager = TaskManager()
results_store: Dict[str, Dict[str, Any]] = {}
llm_reports: Dict[str, Dict[str, Any]] = {}
auto_pentest_orchestrator = AutoPentestOrchestrator(
    llm_pipeline=llm_pipeline,
    nmap_scanner=nmap_scanner,
    recon_engine=recon_engine,
    attack_orchestrator=attack_orchestrator,
    results_store=results_store,
    task_manager=task_manager,
)


def _resolve_api_key(record: Optional[Any], env_var: str) -> Optional[str]:
    return os.getenv(env_var) or (record.api_key if record else None)


def _apply_summary(payload: Dict[str, Any], summary_payload: tuple[Optional[str], Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    summary_text, action_summary = summary_payload
    if summary_text:
        payload["summary"] = summary_text
    if action_summary:
        payload["action_summary"] = action_summary
    return payload


async def get_shodan_client(db: AsyncSession) -> ShodanClient:
    api_key_record = await crud.get_api_key(db, "shodan")
    api_key = _resolve_api_key(api_key_record, "SHODAN_API_KEY")
    return ShodanClient(api_key)


async def get_virustotal_client(db: AsyncSession) -> VirusTotalClient:
    api_key_record = await crud.get_api_key(db, "virustotal")
    api_key = _resolve_api_key(api_key_record, "VIRUSTOTAL_API_KEY")
    return VirusTotalClient(api_key)


@app.on_event("startup")
async def on_startup() -> None:
    await create_tables()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    await llm_pipeline.aclose()


@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": "ReconScope Backend",
        "version": app.version,
        "modules": ["recon", "scanners", "attack", "llm"],
        "docs": "/docs",
        "endpoints": {
            "recon": [
                "POST /intelligence/basic",
                "POST /intelligence/comprehensive",
                "POST /intelligence/batch",
            ],
            "scanners": [
                "POST /scan/nmap",
                "POST /scan/comprehensive",
                "GET /results/{scan_id}",
            ],
            "attack": [
                "POST /attack/execute",
                "POST /attack/run",
                "GET /attack/modules",
            ],
            "llm": [
                "POST /llm/scan",
                "GET /llm/reports/{report_id}",
            ],
        },
    }


@app.get("/health")
async def health(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    from sqlalchemy import text

    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"error: {exc}"

    nmap_status = "available"
    try:
        await nmap_scanner.quick_scan("scanme.nmap.org")
    except Exception as exc:
        nmap_status = f"error: {exc}"

    shodan_client = await get_shodan_client(db)
    vt_client = await get_virustotal_client(db)

    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "database": db_status,
            "nmap": nmap_status,
            "shodan": "configured" if shodan_client.api_key else "missing_api_key",
            "virustotal": "configured" if vt_client.api_key else "missing_api_key",
            "attack_engine": "ready",
            "llm_pipeline": "ready",
        },
    }


@app.post("/intelligence/basic")
async def basic_intelligence(request: IntelligenceRequest) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    data = await loop.run_in_executor(
        None, recon_engine.gather, request.target, request.target_type.value
    )

    event_id = f"recon_basic_{uuid.uuid4().hex[:8]}"
    payload = {
        "event_id": event_id,
        "type": "recon.basic",
        "timestamp": datetime.utcnow().isoformat(),
        "data": data,
        "label": request.label,
    }
    _apply_summary(payload, build_scan_summary(data))
    results_store[event_id] = payload
    return payload


@app.post("/intelligence/comprehensive")
async def comprehensive_intelligence(request: IntelligenceRequest) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    event = await loop.run_in_executor(
        None, recon_engine.comprehensive_scan, request.target, request.target_type.value
    )
    event_dict = event.to_dict()
    if request.label:
        event_dict["label"] = request.label
    _apply_summary(event_dict, build_scan_summary(event_dict.get("data")))
    results_store[event.event_id] = event_dict
    return event_dict


@app.post("/intelligence/batch")
async def batch_intelligence(
    request: BatchScanRequest, background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    task_id = f"batch_recon_{uuid.uuid4().hex[:8]}"
    task_manager.create(
        task_id,
        "recon.batch",
        {"target_count": len(request.targets), "label": request.label},
    )
    results_store[task_id] = {
        "event_id": task_id,
        "task_id": task_id,
        "type": "recon.batch",
        "status": "processing",
        "timestamp": datetime.utcnow().isoformat(),
        "targets": request.targets,
        "label": request.label,
    }

    async def run_batch() -> None:
        loop = asyncio.get_event_loop()
        batch_results: List[Dict[str, Any]] = []
        try:
            task_manager.mark_running(task_id)
            for target in request.targets:
                await task_manager.checkpoint(task_id)
                try:
                    data = await loop.run_in_executor(
                        None, recon_engine.gather, target, request.target_type.value
                    )
                    batch_results.append({"target": target, "status": "completed", "data": data})
                except Exception as exc:  # pragma: no cover
                    batch_results.append({"target": target, "status": "failed", "error": str(exc)})

            results_store[task_id] = {
                "event_id": task_id,
                "task_id": task_id,
                "type": "recon.batch",
                "status": "completed",
                "timestamp": datetime.utcnow().isoformat(),
                "data": batch_results,
                "label": request.label,
            }
            task_manager.mark_completed(task_id)
        except TaskCancelledError as cancel_exc:
            results_store[task_id] = {
                "event_id": task_id,
                "task_id": task_id,
                "type": "recon.batch",
                "status": "cancelled",
                "timestamp": datetime.utcnow().isoformat(),
                "data": batch_results,
                "error": str(cancel_exc),
                "label": request.label,
            }
            task_manager.mark_cancelled(task_id, str(cancel_exc))
        except Exception as exc:  # pragma: no cover
            results_store[task_id] = {
                "event_id": task_id,
                "task_id": task_id,
                "type": "recon.batch",
                "status": "failed",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(exc),
                "data": batch_results,
                "label": request.label,
            }
            task_manager.mark_failed(task_id, str(exc))

    background_tasks.add_task(run_batch)
    return {"task_id": task_id, "status": "processing"}


@app.post("/scan/nmap")
async def nmap_scan(
    request: ScanRequest, db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    try:
        if request.scan_type == ScanType.QUICK:
            result = await nmap_scanner.quick_scan(request.target)
        elif request.scan_type == ScanType.FULL:
            result = await nmap_scanner.full_scan(request.target)
        elif request.scan_type == ScanType.VULN:
            result = await nmap_scanner.scan_target(request.target, "-sV --script vuln")
        else:
            arguments = request.arguments or "-sS -sV"
            result = await nmap_scanner.scan_target(request.target, arguments)

        db_record = await crud.create_scan_result(
            db=db,
            target=request.target,
            scan_type=f"nmap_{request.scan_type.value}",
            status="completed",
            data=result,
        )

        payload = {
            "scan_id": db_record.scan_id,
            "status": "completed",
            "target": request.target,
            "type": f"nmap_{request.scan_type.value}",
            "data": result,
            "timestamp": datetime.utcnow().isoformat(),
            "label": request.label,
        }
        _apply_summary(payload, build_scan_summary(result))
        results_store[db_record.scan_id] = payload
        return payload
    except Exception as exc:
        await crud.create_scan_result(
            db=db,
            target=request.target,
            scan_type=f"nmap_{request.scan_type.value}",
            status="error",
            error=str(exc),
        )
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/scan/comprehensive")
async def comprehensive_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    scan_record = await crud.create_scan_result(
        db=db,
        target=request.target,
        scan_type="comprehensive",
        status="started",
    )
    task_manager.create(
        scan_record.scan_id,
        "scan.comprehensive",
        {"target": request.target, "scan_type": "comprehensive", "label": request.label},
    )
    results_store[scan_record.scan_id] = {
        "scan_id": scan_record.scan_id,
        "task_id": scan_record.scan_id,
        "status": "started",
        "type": "scan.comprehensive",
        "target": request.target,
        "timestamp": datetime.utcnow().isoformat(),
        "label": request.label,
    }

    async def perform() -> None:
        try:
            task_manager.mark_running(scan_record.scan_id)
            await task_manager.checkpoint(scan_record.scan_id)
            results: Dict[str, Any] = {}
            results["nmap"] = await nmap_scanner.quick_scan(request.target)

            await task_manager.checkpoint(scan_record.scan_id)
            shodan_client = await get_shodan_client(db)
            if shodan_client.api_key:
                shodan_data = await asyncio.to_thread(shodan_client.get_host, request.target)
                results["shodan"] = shodan_data

            await task_manager.checkpoint(scan_record.scan_id)
            vt_client = await get_virustotal_client(db)
            if vt_client.api_key:
                vt_data = await asyncio.to_thread(vt_client.get_ip_info, request.target)
                results["virustotal"] = vt_data

            await crud.update_scan_result(
                db=db,
                scan_id=scan_record.scan_id,
                status="completed",
                data=results,
            )
            payload = {
                "scan_id": scan_record.scan_id,
                "task_id": scan_record.scan_id,
                "status": "completed",
                "data": results,
                "label": request.label,
            }
            _apply_summary(payload, build_scan_summary(results))
            results_store[scan_record.scan_id] = payload
            task_manager.mark_completed(scan_record.scan_id)
        except TaskCancelledError as cancel_exc:
            await crud.update_scan_result(
                db=db,
                scan_id=scan_record.scan_id,
                status="cancelled",
                error=str(cancel_exc),
            )
            results_store[scan_record.scan_id] = {
                "scan_id": scan_record.scan_id,
                "task_id": scan_record.scan_id,
                "status": "cancelled",
                "target": request.target,
                "type": "scan.comprehensive",
                "error": str(cancel_exc),
                "timestamp": datetime.utcnow().isoformat(),
                "label": request.label,
            }
            task_manager.mark_cancelled(scan_record.scan_id, str(cancel_exc))
        except Exception as exc:  # pragma: no cover
            await crud.update_scan_result(
                db=db,
                scan_id=scan_record.scan_id,
                status="error",
                error=str(exc),
            )
            results_store[scan_record.scan_id] = {
                "scan_id": scan_record.scan_id,
                "task_id": scan_record.scan_id,
                "status": "failed",
                "target": request.target,
                "type": "scan.comprehensive",
                "error": str(exc),
                "timestamp": datetime.utcnow().isoformat(),
                "label": request.label,
            }
            task_manager.mark_failed(scan_record.scan_id, str(exc))

    background_tasks.add_task(perform)
    return {"scan_id": scan_record.scan_id, "status": "started"}


@app.get("/results/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    record = await crud.get_scan_result(db, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": record.scan_id,
        "target": record.target,
        "type": record.scan_type,
        "status": record.status,
        "data": record.data,
        "error": record.error,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }


@app.post("/attack/execute")
async def execute_attack(request: AttackRequest) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    try:
        event = await loop.run_in_executor(
            None,
            partial(
                attack_orchestrator.execute_attack,
                request.attack_type.value,
                request.target,
                parameters=request.parameters,
                profile=TestingModel(request.profile.value),
                dry_run=request.dry_run,
                sla=request.sla,
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    event_dict = event.to_dict()
    if request.label:
        event_dict["label"] = request.label
    _apply_summary(event_dict, build_attack_summary(event_dict.get("data")))
    results_store[event.event_id] = event_dict
    return event_dict


@app.post("/attack/run")
async def run_batch_attack(request: AttackRunRequest) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    tasks = []
    for target in request.targets:
        params = dict(request.parameters)
        params.update(target.metadata or {})
        if target.service:
            params.setdefault("service", target.service)
        if target.port:
            params.setdefault("port", target.port)

        tasks.append(
            loop.run_in_executor(
                None,
                partial(
                    attack_orchestrator.execute_attack,
                    request.attack_type.value,
                    target.value,
                    parameters=params,
                    profile=TestingModel(request.profile.value),
                    dry_run=request.dry_run,
                    sla=request.sla,
                ),
            )
        )

    executions = await asyncio.gather(*tasks, return_exceptions=True)
    payload: List[Dict[str, Any]] = []
    for execution in executions:
        if hasattr(execution, "to_dict"):
            event_dict = execution.to_dict()
            _apply_summary(event_dict, build_attack_summary(event_dict.get("data")))
            results_store[event_dict["event_id"]] = event_dict
            payload.append({"status": "completed", "event": event_dict})
        else:
            payload.append({"status": "failed", "error": str(execution)})

    return {"count": len(payload), "results": payload}


@app.get("/attack/modules")
async def attack_modules() -> Dict[str, Any]:
    modules = attack_orchestrator.list_modules()
    return {"modules": modules, "count": len(modules)}


@app.post("/autopentest/start")
async def autopentest_start(request: AutoPentestRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    run = await auto_pentest_orchestrator.create_run(
        target=request.target,
        profile=request.profile.value,
        goal=request.goal,
        scope=request.scope,
        notes=request.notes,
        label=request.label,
    )
    background_tasks.add_task(auto_pentest_orchestrator.execute_run, run.run_id)
    return {"run_id": run.run_id, "run": run.to_dict()}


@app.get("/autopentest/{run_id}")
async def autopentest_status(run_id: str) -> Dict[str, Any]:
    run = auto_pentest_orchestrator.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Autopentest run not found")
    return run


@app.get("/autopentest")
async def autopentest_history() -> Dict[str, Any]:
    return {"items": auto_pentest_orchestrator.list_runs()}


@app.get("/tasks")
async def list_tasks() -> Dict[str, Any]:
    return {"items": task_manager.list()}


@app.get("/tasks/{task_id}")
async def get_task(task_id: str) -> Dict[str, Any]:
    control = task_manager.get(task_id)
    if not control:
        raise HTTPException(status_code=404, detail="Задача не найдена")
    return control.to_dict()


@app.post("/tasks/{task_id}/pause")
async def pause_task(task_id: str) -> Dict[str, Any]:
    try:
        control = task_manager.pause(task_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Задача не найдена")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return control.to_dict()


@app.post("/tasks/{task_id}/resume")
async def resume_task(task_id: str) -> Dict[str, Any]:
    try:
        control = task_manager.resume(task_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Задача не найдена")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return control.to_dict()


@app.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, request: TaskActionRequest) -> Dict[str, Any]:
    try:
        control = task_manager.cancel(task_id, request.reason)
    except KeyError:
        raise HTTPException(status_code=404, detail="Задача не найдена")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return control.to_dict()


@app.post("/llm/scan")
async def llm_scan(
    request: LLMScanRequest, background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    task_id = f"llm_scan_{uuid.uuid4().hex[:8]}"
    task_manager.create(task_id, "llm.scan", {"target": request.url, "goal": request.goal, "label": request.label})

    results_store[task_id] = {
        "event_id": task_id,
        "task_id": task_id,
        "type": "llm.scan",
        "status": "processing",
        "target": request.url,
        "goal": request.goal,
        "timestamp": datetime.utcnow().isoformat(),
        "metadata": request.metadata,
        "label": request.label,
    }

    async def run_llm() -> None:
        try:
            task_manager.mark_running(task_id)
            await task_manager.checkpoint(task_id)
            options = ScanOptions(
                model=request.model,
                provider=request.provider,
                temperature=request.temperature,
                max_output_tokens=request.max_output_tokens,
                use_browser=request.use_browser,
            )
            report = await llm_pipeline.run(
                url=request.url,
                scan_goal=request.goal,
                options=options,
            )
            payload = {
                "report_id": task_id,
                "status": "completed",
                "report": asdict(report),
                "metadata": request.metadata,
                "label": request.label,
            }
            llm_reports[task_id] = payload
            results_store[task_id] = {
                "event_id": task_id,
                "task_id": task_id,
                "type": "llm.scan",
                "status": "completed",
                "target": request.url,
                "goal": request.goal,
                "timestamp": datetime.utcnow().isoformat(),
                "report": asdict(report),
                "metadata": request.metadata,
                "label": request.label,
            }
            task_manager.mark_completed(task_id)
        except TaskCancelledError as cancel_exc:
            llm_reports[task_id] = {
                "report_id": task_id,
                "status": "cancelled",
                "error": str(cancel_exc),
                "label": request.label,
            }
            results_store[task_id] = {
                "event_id": task_id,
                "task_id": task_id,
                "type": "llm.scan",
                "status": "cancelled",
                "target": request.url,
                "goal": request.goal,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(cancel_exc),
                "metadata": request.metadata,
                "label": request.label,
            }
            task_manager.mark_cancelled(task_id, str(cancel_exc))
        except Exception as exc:  # pragma: no cover
            llm_reports[task_id] = {"report_id": task_id, "status": "failed", "error": str(exc)}
            results_store[task_id] = {
                "event_id": task_id,
                "task_id": task_id,
                "type": "llm.scan",
                "status": "failed",
                "target": request.url,
                "goal": request.goal,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(exc),
                "metadata": request.metadata,
                "label": request.label,
            }
            task_manager.mark_failed(task_id, str(exc))

    background_tasks.add_task(run_llm)
    return {"task_id": task_id, "status": "processing"}


@app.get("/llm/reports/{report_id}")
async def get_llm_report(report_id: str) -> Dict[str, Any]:
    report = llm_reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/history")
async def history() -> Dict[str, Any]:
    items = list(results_store.values())
    items.sort(
        key=lambda item: item.get("timestamp")
        or item.get("updated_at")
        or item.get("created_at")
        or "",
        reverse=True,
    )
    return {"count": len(items), "items": items}


@app.get("/history/{event_id}")
async def history_item(event_id: str) -> Dict[str, Any]:
    if event_id not in results_store:
        raise HTTPException(status_code=404, detail="Event not found")
    return results_store[event_id]


__all__ = ["app"]

