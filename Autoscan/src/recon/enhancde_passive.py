from src.integrations.shodan import ShodanClient
from src.integrations.virustotal import VirusTotalClient
from src.integrations.nmap import NmapScanner
from src.core.events import BaseEvent
from src.core.contracts import IntelligenceProvider
from datetime import datetime
from typing import Dict, Any, List
import ipaddress

class EnhancedPassiveRecon(IntelligenceProvider):
    """Улучшенный пассивный сбор данных с валидацией"""
    
    def __init__(self):
        self.shodan = ShodanClient()
        self.vt = VirusTotalClient()
        self.nmap = NmapScanner()
    
    @property
    def provider_name(self) -> str:
        return "enhanced_passive_recon"
    
    def _validate_target(self, target: str, target_type: str) -> bool:
        """Валидация цели"""
        try:
            if target_type == "ip":
                ipaddress.ip_address(target)
                return True
            elif target_type == "domain":
                # Простая валидация домена
                return len(target) > 0 and '.' in target
            elif target_type == "network":
                ipaddress.ip_network(target, strict=False)
                return True
            return False
        except ValueError:
            return False
    
    def gather(self, target: str, target_type: str = "ip") -> Dict[str, Any]:
        """Сбор разведданных с валидацией"""
        if not self._validate_target(target, target_type):
            return {"error": f"Invalid target: {target} for type: {target_type}"}
        
        results = {}
        
        # Базовый сбор для всех типов целей
        if target_type in ["ip", "domain"]:
            # Nmap быстрый сканинг
            nmap_result = self.nmap.quick_scan(target)
            if "error" not in nmap_result:
                results["network_scan"] = nmap_result
        
        # Специфичный сбор для IP
        if target_type == "ip":
            results.update(self._gather_ip_intel(target))
        
        # Специфичный сбор для домена
        elif target_type == "domain":
            results.update(self._gather_domain_intel(target))
        
        # Сбор для сети
        elif target_type == "network":
            results.update(self._gather_network_intel(target))
        
        return results
    
    def _gather_ip_intel(self, ip: str) -> Dict[str, Any]:
        """Сбор информации об IP"""
        results = {}
        
        # Shodan информация
        shodan_result = self.shodan.get_host(ip)
        if "error" not in shodan_result:
            results["shodan"] = shodan_result
        
        # VirusTotal информация
        vt_result = self.vt.get_ip_info(ip)
        if "error" not in vt_result:
            results["virustotal"] = vt_result
        
        return results
    
    def _gather_domain_intel(self, domain: str) -> Dict[str, Any]:
        """Сбор информации о домене"""
        results = {}
        
        # VirusTotal информация о домене
        vt_result = self.vt.get_domain_info(domain)
        if "error" not in vt_result:
            results["virustotal"] = vt_result
        
        # DNS информация через nmap
        dns_scan = self.nmap.scan_target(domain, "-sn --dns-servers 8.8.8.8")
        if "error" not in dns_scan:
            results["dns_info"] = dns_scan
        
        return results
    
    def _gather_network_intel(self, network: str) -> Dict[str, Any]:
        """Сбор информации о сети"""
        results = {}
        
        # Обнаружение хостов в сети
        network_scan = self.nmap.scan_target(network, "-sn")
        if "error" not in network_scan:
            results["network_discovery"] = network_scan
        
        return results
    
    def comprehensive_scan(self, target: str, target_type: str = "ip") -> BaseEvent:
        """Комплексное сканирование"""
        intelligence = self.gather(target, target_type)
        
        return BaseEvent(
            event_id=f"comprehensive_{target_type}_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            event_type="comprehensive_recon",
            source=self.provider_name,
            data=intelligence
        )