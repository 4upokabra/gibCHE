from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import asyncio
import uuid
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from src.integrations.nmap import NmapScanner
from src.integrations.shodan import ShodanClient
from src.integrations.virustotal import VirusTotalClient
from src.core.database import get_db, create_tables
from src.core import crud
import os

app = FastAPI(
    title="Intelligence API",
    version="3.0.0",
    description="Система разведки с PostgreSQL и мгновенными результатами"
)

# Инициализация интеграций
nmap_scanner = NmapScanner()

# Получаем API ключи из БД
async def get_shodan_client(db: AsyncSession):
    api_key_record = await crud.get_api_key(db, "shodan")
    api_key = api_key_record.api_key if api_key_record else os.getenv('SHODAN_API_KEY')
    return ShodanClient(api_key)

async def get_virustotal_client(db: AsyncSession):
    api_key_record = await crud.get_api_key(db, "virustotal")
    api_key = api_key_record.api_key if api_key_record else os.getenv('VIRUSTOTAL_API_KEY')
    return VirusTotalClient(api_key)

# Модели запросов
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"

class ShodanSearchRequest(BaseModel):
    query: str
    limit: int = 10

class APIKeyRequest(BaseModel):
    service: str
    api_key: str

# События при запуске
@app.on_event("startup")
async def startup_event():
    await create_tables()
    print("✅ База данных инициализирована")

@app.get("/")
async def root(db: AsyncSession = Depends(get_db)):
    shodan_client = await get_shodan_client(db)
    vt_client = await get_virustotal_client(db)
    
    shodan_status = "available" if shodan_client.api_key else "missing_api_key"
    vt_status = "available" if vt_client.api_key else "missing_api_key"
    
    return {
        "message": "🔍 Intelligence API с PostgreSQL",
        "status": "running",
        "integrations": {
            "nmap": "available",
            "shodan": shodan_status,
            "virustotal": vt_status,
            "database": "postgresql"
        },
        "endpoints": {
            "nmap_scan": "POST /scan/nmap - сразу возвращает результат",
            "shodan_host": "POST /shodan/host - сразу возвращает результат",
            "shodan_search": "POST /shodan/search - сразу возвращает результат",
            "virustotal": "POST /virustotal/check - сразу возвращает результат",
            "comprehensive": "POST /scan/comprehensive - фоновая задача",
            "results": "GET /results/{id} - получить результат из БД",
            "history": "GET /history - история сканирований",
            "api_keys": "POST /api-keys - управление API ключами"
        }
    }

@app.post("/scan/nmap")
async def nmap_scan(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    """Nmap сканирование - сразу возвращает результат и сохраняет в БД"""
    try:
        # Выполняем сканирование
        if request.scan_type == "quick":
            result_data = await nmap_scanner.quick_scan(request.target)
        elif request.scan_type == "full":
            result_data = await nmap_scanner.full_scan(request.target)
        else:
            result_data = await nmap_scanner.scan_target(request.target)
        
        # Сохраняем в БД
        db_scan = await crud.create_scan_result(
            db=db,
            target=request.target,
            scan_type=f"nmap_{request.scan_type}",
            status="completed",
            data=result_data
        )
        
        return {
            "scan_id": db_scan.scan_id,
            "status": "completed",
            "target": request.target,
            "type": f"nmap_{request.scan_type}",
            "data": result_data,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        # Сохраняем ошибку в БД
        await crud.create_scan_result(
            db=db,
            target=request.target,
            scan_type=f"nmap_{request.scan_type}",
            status="error",
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/shodan/host")
async def shodan_host_info(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    """Информация о хосте из Shodan"""
    try:
        shodan_client = await get_shodan_client(db)
        result_data = shodan_client.get_host(request.target)
        
        # Сохраняем в БД
        db_scan = await crud.create_scan_result(
            db=db,
            target=request.target,
            scan_type="shodan_host",
            status="completed",
            data=result_data
        )
        
        return {
            "scan_id": db_scan.scan_id,
            "status": "completed",
            "target": request.target,
            "type": "shodan_host",
            "data": result_data,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        await crud.create_scan_result(
            db=db,
            target=request.target,
            scan_type="shodan_host",
            status="error",
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/shodan/search")
async def shodan_search(request: ShodanSearchRequest, db: AsyncSession = Depends(get_db)):
    """Поиск в Shodan"""
    try:
        shodan_client = await get_shodan_client(db)
        result_data = shodan_client.search(request.query, request.limit)
        
        db_scan = await crud.create_scan_result(
            db=db,
            target=request.query,
            scan_type="shodan_search",
            status="completed",
            data=result_data
        )
        
        return {
            "scan_id": db_scan.scan_id,
            "status": "completed",
            "query": request.query,
            "type": "shodan_search",
            "data": result_data,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        await crud.create_scan_result(
            db=db,
            target=request.query,
            scan_type="shodan_search",
            status="error",
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/virustotal/check")
async def virustotal_check(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    """Проверка в VirusTotal"""
    try:
        vt_client = await get_virustotal_client(db)
        
        # Определяем тип цели
        if '.' in request.target and not request.target[0].isdigit():
            result_data = vt_client.get_domain_info(request.target)
        else:
            result_data = vt_client.get_ip_info(request.target)
        
        db_scan = await crud.create_scan_result(
            db=db,
            target=request.target,
            scan_type="virustotal",
            status="completed",
            data=result_data
        )
        
        return {
            "scan_id": db_scan.scan_id,
            "status": "completed",
            "target": request.target,
            "type": "virustotal",
            "data": result_data,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        await crud.create_scan_result(
            db=db,
            target=request.target,
            scan_type="virustotal",
            status="error",
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/comprehensive")
async def comprehensive_scan(request: ScanRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Комплексное сканирование всеми инструментами"""
    scan_record = await crud.create_scan_result(
        db=db,
        target=request.target,
        scan_type="comprehensive",
        status="started"
    )
    
    async def perform_comprehensive_scan():
        try:
            results = {}
            
            # Nmap сканирование
            nmap_result = await nmap_scanner.quick_scan(request.target)
            results["nmap"] = nmap_result
            
            # Shodan информация
            shodan_client = await get_shodan_client(db)
            if shodan_client.api_key:
                shodan_result = await asyncio.to_thread(shodan_client.get_host, request.target)
                results["shodan"] = shodan_result
            
            # VirusTotal информация
            vt_client = await get_virustotal_client(db)
            if vt_client.api_key:
                if '.' in request.target and not request.target[0].isdigit():
                    vt_result = await asyncio.to_thread(vt_client.get_domain_info, request.target)
                else:
                    vt_result = await asyncio.to_thread(vt_client.get_ip_info, request.target)
                results["virustotal"] = vt_result
            
            # Обновляем запись в БД
            await crud.update_scan_result(
                db=db,
                scan_id=scan_record.scan_id,
                status="completed",
                data=results
            )
            
        except Exception as e:
            await crud.update_scan_result(
                db=db,
                scan_id=scan_record.scan_id,
                status="error",
                error=str(e)
            )
    
    background_tasks.add_task(perform_comprehensive_scan)
    
    return {
        "scan_id": scan_record.scan_id,
        "status": "started",
        "message": "Комплексное сканирование запущено в фоне"
    }

@app.get("/results/{scan_id}")
async def get_results(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Получить результаты сканирования из БД"""
    scan_record = await crud.get_scan_result(db, scan_id)
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan_record.scan_id,
        "target": scan_record.target,
        "type": scan_record.scan_type,
        "status": scan_record.status,
        "data": scan_record.data,
        "error": scan_record.error,
        "created_at": scan_record.created_at.isoformat(),
        "updated_at": scan_record.updated_at.isoformat()
    }

@app.get("/history")
async def get_scan_history(skip: int = 0, limit: int = 50, db: AsyncSession = Depends(get_db)):
    """Получить историю сканирований"""
    scans = await crud.get_scan_results(db, skip=skip, limit=limit)
    
    return {
        "total": len(scans),
        "scans": [
            {
                "scan_id": scan.scan_id,
                "target": scan.target,
                "type": scan.scan_type,
                "status": scan.status,
                "created_at": scan.created_at.isoformat(),
                "updated_at": scan.updated_at.isoformat()
            }
            for scan in scans
        ]
    }

@app.get("/history/{target}")
async def get_target_history(target: str, db: AsyncSession = Depends(get_db)):
    """Получить историю сканирований для конкретной цели"""
    scans = await crud.get_scan_results_by_target(db, target)
    
    return {
        "target": target,
        "total_scans": len(scans),
        "scans": [
            {
                "scan_id": scan.scan_id,
                "type": scan.scan_type,
                "status": scan.status,
                "created_at": scan.created_at.isoformat()
            }
            for scan in scans
        ]
    }

@app.post("/api-keys")
async def set_api_key(request: APIKeyRequest, db: AsyncSession = Depends(get_db)):
    """Установить API ключ для сервиса"""
    if request.service not in ["shodan", "virustotal"]:
        raise HTTPException(status_code=400, detail="Service must be 'shodan' or 'virustotal'")
    
    api_key_record = await crud.create_or_update_api_key(
        db=db,
        service=request.service,
        api_key=request.api_key
    )
    
    return {
        "status": "success",
        "service": request.service,
        "message": f"API key for {request.service} has been saved"
    }

@app.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Проверка здоровья системы и БД"""
    try:
        # Проверяем подключение к БД
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    # Проверяем Nmap
    nmap_status = "available"
    try:
        test_result = await nmap_scanner.quick_scan("scanme.nmap.org")
        if "error" in test_result:
            nmap_status = "error"
    except:
        nmap_status = "error"
    
    # Проверяем API ключи
    shodan_client = await get_shodan_client(db)
    vt_client = await get_virustotal_client(db)
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "database": db_status,
            "nmap": nmap_status,
            "shodan": "available" if shodan_client.api_key else "missing_api_key",
            "virustotal": "available" if vt_client.api_key else "missing_api_key"
        }
    }