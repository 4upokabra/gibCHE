import requests
from typing import Dict, Any

class VirusTotalClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        """Получение информации об IP"""
        if not self.api_key:
            return {
                "source": "virustotal", 
                "ip": ip,
                "note": "API key not provided",
                "data": {}
            }
        
        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(f"{self.base_url}/ip_addresses/{ip}", 
                                  headers=headers, timeout=10)
            response.raise_for_status()
            
            return {
                "source": "virustotal",
                "ip": ip,
                "data": response.json()
            }
        except Exception as e:
            return {"error": f"VirusTotal request failed: {str(e)}"}

    def get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Получение информации о домене"""
        if not self.api_key:
            return {
                "source": "virustotal",
                "domain": domain,
                "note": "API key not provided", 
                "data": {}
            }
        
        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(f"{self.base_url}/domains/{domain}",
                                  headers=headers, timeout=10)
            response.raise_for_status()
            
            return {
                "source": "virustotal", 
                "domain": domain,
                "data": response.json()
            }
        except Exception as e:
            return {"error": f"VirusTotal request failed: {str(e)}"}