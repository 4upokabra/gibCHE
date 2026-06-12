from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from enum import Enum

class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    NETWORK = "network"

class ScanType(str, Enum):
    QUICK = "quick"
    FULL = "full"
    VULN = "vuln"
    CUSTOM = "custom"

class IntelligenceRequest(BaseModel):
    target: str = Field(..., description="Цель сканирования (IP, домен или сеть)")
    target_type: TargetType = Field(TargetType.IP, description="Тип цели")

class ScanRequest(BaseModel):
    target: str = Field(..., description="Цель сканирования")
    scan_type: ScanType = Field(ScanType.QUICK, description="Тип сканирования Nmap")
    arguments: Optional[str] = Field(None, description="Пользовательские аргументы Nmap")

class IntelligenceResponse(BaseModel):
    task_id: str
    status: str
    type: str
    result: Optional[Dict[str, Any]] = None