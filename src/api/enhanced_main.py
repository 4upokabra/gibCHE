from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from enum import Enum

from src.recon.enhanced_passive import EnhancedPassiveRecon
from src.attack.core import AttackOrchestrator
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
    PORT_SCAN = "port_scan"
    VULN_SCAN = "vuln_scan"

class IntelligenceRequest(BaseModel):
    target: str = Field(..., description="Цель сканирования")
    target_type: TargetType = Field(TargetType.IP, description="Тип цели")
    comprehensive: bool = Field(False, description="Комплексное сканирование")

class AttackRequest(BaseModel):
    target: str = Field(..., description="Цель атаки")
    attack_type: AttackType = Field(..., description="Тип атаки")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)

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
        event = await asyncio.get_event_loop().run_in_executor(
            None, attack_orchestrator.execute_attack, 
            request.attack_type, request.target
        )
        
        # Сохраняем результат
        results_store[event.event_id] = event.to_dict()
        
        return event.to_dict()
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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