from src.core.queue import celery_app
from src.recon.passive import PassiveRecon
from src.integrations.nmap import NmapScanner
from src.core.events import BaseEvent, EventType
from datetime import datetime
import time

@celery_app.task
def quick_recon_task(target: str, target_type: str = "ip") -> dict:
    """Задача быстрой разведки"""
    recon = PassiveRecon()
    event = recon.gather_intelligence(target, target_type)
    return event.dict()

@celery_app.task
def deep_scan_task(target: str) -> dict:
    """Задача глубокого сканирования"""
    recon = PassiveRecon()
    event = recon.deep_scan(target)
    return event.dict()

@celery_app.task
def nmap_scan_task(target: str, scan_type: str = "quick") -> dict:
    """Задача сканирования Nmap"""
    scanner = NmapScanner()
    
    if scan_type == "quick":
        result = scanner.quick_scan(target)
    elif scan_type == "full":
        result = scanner.full_scan(target)
    elif scan_type == "vuln":
        result = scanner.vulnerability_scan(target)
    else:
        result = scanner.scan_target(target)
    
    event = BaseEvent(
        event_id=f"nmap_{scan_type}_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        type=EventType.RECON,
        source="nmap",
        timestamp=datetime.now(),
        data=result
    )
    
    return event.dict()