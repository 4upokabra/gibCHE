from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from enum import Enum
from functools import partial

from src.recon.enhanced_passive import EnhancedPassiveRecon
from src.attack.core import AttackOrchestrator, TestingModel, AttackVector
from src.core.events import BaseEvent, EventSerializer
import asyncio
import uuid

app = FastAPI(
    title="Advanced Intelligence API", 
    version="3.0.0",
    description="Модульная система разведки и атак"
)

# Инициализация компонентов
recon_engine = EnhancedPassiveRecon()
attack_orchestrator = AttackOrchestrator()

# Модели запросов
class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    NETWORK = "network"

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
    target: str = Field(..., description="Цель сканирования")
    target_type: TargetType = Field(TargetType.IP, description="Тип цели")
    comprehensive: bool = Field(False, description="Комплексное сканирование")

class AttackRequest(BaseModel):
    target: str = Field(..., description="Цель атаки")
    attack_type: AttackType = Field(..., description="Тип атаки")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    profile: TestingProfile = Field(TestingProfile.BLACK, description="Модель тестирования")
    dry_run: bool = Field(False, description="Только валидация без запуска")
    sla: Optional[str] = Field(None, description="Требования SLA/окна запуска")


class AttackTargetPayload(BaseModel):
    value: str = Field(..., description="Идентификатор цели (IP/домен/URL)")
    service: Optional[str] = Field(None, description="Сервис (ssh, http, mssql, etc.)")
    port: Optional[int] = Field(None, description="Порт сервиса")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Дополнительные параметры")


class AttackRunRequest(BaseModel):
    attack_type: AttackType = Field(..., description="Тип атаки")
    targets: List[AttackTargetPayload] = Field(..., description="Список целей")
    profile: TestingProfile = Field(TestingProfile.BLACK, description="Модель тестирования")
    dry_run: bool = Field(False, description="Режим dry-run")
    sla: Optional[str] = Field(None, description="Окно SLA")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Общие параметры атаки")

class BatchScanRequest(BaseModel):
    targets: List[str] = Field(..., description="Список целей")
    target_type: TargetType = Field(TargetType.IP, description="Тип целей")

# Хранилище результатов (в памяти)
results_store = {}

@app.post("/intelligence/basic")
async def basic_intelligence(request: IntelligenceRequest):
    """Базовая разведка"""
    try:
        intelligence_data = await asyncio.get_event_loop().run_in_executor(
            None, recon_engine.gather, request.target, request.target_type
        )
        
        event = BaseEvent(
            event_id=f"basic_{str(uuid.uuid4())[:8]}",
            event_type="recon",
            source="basic_intelligence",
            data=intelligence_data
        )
        
        # Сохраняем результат
        results_store[event.event_id] = event.to_dict()
        
        return event.to_dict()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/intelligence/comprehensive")
async def comprehensive_intelligence(request: IntelligenceRequest):
    """Комплексная разведка"""
    try:
        event = await asyncio.get_event_loop().run_in_executor(
            None, recon_engine.comprehensive_scan, request.target, request.target_type
        )
        
        # Сохраняем результат
        results_store[event.event_id] = event.to_dict()
        
        return event.to_dict()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/attack/execute")
async def execute_attack(request: AttackRequest):
    """Выполнение атаки"""
    try:
        loop = asyncio.get_event_loop()
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
        
        # Сохраняем результат
        results_store[event.event_id] = event.to_dict()
        
        return event.to_dict()
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/attack/run")
async def run_attack_batch(request: AttackRunRequest):
    """Новый эндпоинт attack/run согласно ТЗ Dev B."""
    loop = asyncio.get_event_loop()
    tasks = []

    for target in request.targets:
        params = dict(request.parameters)
        if target.metadata:
            params.update(target.metadata)
        if target.service:
            params.setdefault("service", target.service)
        if target.port:
            params.setdefault("port", target.port)

        task = loop.run_in_executor(
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
        tasks.append(task)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    payload = []
    for result in results:
        if isinstance(result, BaseEvent):
            results_store[result.event_id] = result.to_dict()
            payload.append({"event": result.to_dict(), "status": "completed"})
        else:
            payload.append({"error": str(result), "status": "failed"})

    return {"count": len(payload), "results": payload}

@app.post("/intelligence/batch")
async def batch_intelligence(request: BatchScanRequest, background_tasks: BackgroundTasks):
    """Пакетное сканирование целей"""
    task_id = str(uuid.uuid4())
    
    async def process_batch():
        results = []
        for target in request.targets:
            try:
                intelligence_data = await asyncio.get_event_loop().run_in_executor(
                    None, recon_engine.gather, target, request.target_type
                )
                results.append({
                    "target": target,
                    "data": intelligence_data,
                    "status": "completed"
                })
            except Exception as e:
                results.append({
                    "target": target,
                    "error": str(e),
                    "status": "failed"
                })
        
        event = BaseEvent(
            event_id=task_id,
            event_type="batch_recon",
            source="batch_intelligence",
            data={"results": results}
        )
        
        results_store[task_id] = event.to_dict()
    
    background_tasks.add_task(process_batch)
    
    return {"task_id": task_id, "status": "processing", "targets_count": len(request.targets)}

@app.get("/results/{event_id}")
async def get_result(event_id: str, format: str = "json"):
    """Получение результата по ID"""
    if event_id not in results_store:
        raise HTTPException(status_code=404, detail="Result not found")
    
    result = results_store[event_id]
    
    if format == "csv":
        # Создаем временный event для сериализации
        event_data = result
        class TempEvent:
            def to_dict(self): return event_data
            def to_csv(self): return EventSerializer.to_csv(self)
        
        temp_event = TempEvent()
        return {"csv": temp_event.to_csv()}
    
    return result

@app.get("/attack/modules")
async def list_attack_modules():
    """Список доступных модулей атак"""
    return {
        "modules": attack_orchestrator.list_modules(),
        "count": len(attack_orchestrator.list_modules())
    }

@app.get("/health")
async def health_check():
    """Проверка здоровья системы"""
    components = {
        "recon_engine": "active",
        "attack_orchestrator": "active",
        "api": "healthy"
    }
    
    return {
        "status": "healthy",
        "version": "3.0.0",
        "components": components
    }

@app.get("/")
async def root():
    """Корневой endpoint с документацией"""
    return {
        "service": "Advanced Intelligence API",
        "version": "3.0.0",
        "endpoints": {
            "intelligence": {
                "basic": "POST /intelligence/basic",
                "comprehensive": "POST /intelligence/comprehensive", 
                "batch": "POST /intelligence/batch"
            },
            "attack": {
                "execute": "POST /attack/execute",
                "modules": "GET /attack/modules"
            },
            "results": "GET /results/{event_id}",
            "health": "GET /health"
        }
    }