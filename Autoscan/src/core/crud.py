from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from .database import ScanResult, APIKey
from typing import List, Optional
import uuid

# ScanResult CRUD operations
async def create_scan_result(db: AsyncSession, target: str, scan_type: str, status: str, data: dict = None, error: str = None):
    scan_id = str(uuid.uuid4())[:12]
    db_scan = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type=scan_type,
        status=status,
        data=data,
        error=error
    )
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)
    return db_scan

async def get_scan_result(db: AsyncSession, scan_id: str):
    result = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
    return result.scalar_one_or_none()

async def get_scan_results(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(
        select(ScanResult)
        .order_by(desc(ScanResult.created_at))
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()

async def get_scan_results_by_target(db: AsyncSession, target: str):
    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.target == target)
        .order_by(desc(ScanResult.created_at))
    )
    return result.scalars().all()

async def update_scan_result(db: AsyncSession, scan_id: str, status: str = None, data: dict = None, error: str = None):
    db_scan = await get_scan_result(db, scan_id)
    if db_scan:
        if status is not None:
            db_scan.status = status
        if data is not None:
            db_scan.data = data
        if error is not None:
            db_scan.error = error
        await db.commit()
        await db.refresh(db_scan)
    return db_scan

# APIKey CRUD operations
async def get_api_key(db: AsyncSession, service: str):
    result = await db.execute(
        select(APIKey)
        .where(APIKey.service == service)
        .where(APIKey.is_active == True)
    )
    return result.scalar_one_or_none()

async def create_or_update_api_key(db: AsyncSession, service: str, api_key: str):
    existing = await get_api_key(db, service)
    if existing:
        existing.api_key = api_key
        await db.commit()
        await db.refresh(existing)
        return existing
    else:
        db_key = APIKey(service=service, api_key=api_key)
        db.add(db_key)
        await db.commit()
        await db.refresh(db_key)
        return db_key