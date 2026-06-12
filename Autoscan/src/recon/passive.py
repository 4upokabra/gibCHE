from src.integrations.shodan import ShodanClient
from src.integrations.virustotal import VirusTotalClient
from src.integrations.nmap import NmapScanner
from src.core.events import BaseEvent
from datetime import datetime

class PassiveRecon:
    def __init__(self):
        self.shodan = ShodanClient()
        self.vt = VirusTotalClient()
        self.nmap = NmapScanner()
    
    async def gather_intelligence(self, target: str, target_type: str = "ip"):
        """Асинхронный сбор разведданных"""
        results = {}
        
        # Nmap сканирование
        nmap_result = await self.nmap.quick_scan(target)
        if "error" not in nmap_result:
            results["nmap"] = nmap_result
        
        # Shodan информация
        shodan_result = self.shodan.get_host(target)
        if "error" not in shodan_result:
            results["shodan"] = shodan_result
        
        # VirusTotal информация
        if target_type == "ip":
            vt_result = self.vt.get_ip_info(target)
        else:
            vt_result = self.vt.get_domain_info(target)
            
        if "error" not in vt_result:
            results["virustotal"] = vt_result
        
        return BaseEvent(
            event_id=f"scan_{target}_{datetime.now().strftime('%H%M%S')}",
            event_type="recon",
            source="docker_intelligence",
            data=results
        )