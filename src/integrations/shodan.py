import shodan
import requests
from typing import Dict, Any, Optional

class ShodanClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        if api_key:
            self.api = shodan.Shodan(api_key)
        else:
            self.api = None
    
    def get_host(self, ip: str) -> Dict[str, Any]:
        """Получение информации о хосте через официальную библиотеку Shodan"""
        if not self.api_key:
            return {
                "source": "shodan",
                "ip": ip,
                "note": "API key not provided. Get free key from https://developer.shodan.io/",
                "data": {}
            }
        
        try:
            host_info = self.api.host(ip)
            
            # Форматируем только важную информацию
            formatted_data = {
                "ip": host_info.get('ip_str'),
                "country": host_info.get('country_name'),
                "city": host_info.get('city'),
                "org": host_info.get('org'),
                "os": host_info.get('os'),
                "ports": host_info.get('ports', []),
                "vulnerabilities": host_info.get('vulns', []),
                "last_update": host_info.get('last_update'),
                "services": []
            }
            
            # Информация о сервисах
            for service in host_info.get('data', []):
                formatted_data["services"].append({
                    "port": service.get('port'),
                    "transport": service.get('transport'),
                    "service": service.get('_shodan', {}).get('module'),
                    "product": service.get('product'),
                    "version": service.get('version'),
                    "banner": service.get('data', '')[:200]  # Ограничиваем размер баннера
                })
            
            return {
                "source": "shodan",
                "ip": ip,
                "data": formatted_data
            }
            
        except shodan.APIError as e:
            return {"error": f"Shodan API error: {str(e)}"}
        except Exception as e:
            return {"error": f"Shodan request failed: {str(e)}"}
    
    def search(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Поиск в Shodan"""
        if not self.api_key:
            return {
                "error": "API key required for search. Get free key from https://developer.shodan.io/"
            }
        
        try:
            results = self.api.search(query, limit=limit)
            
            formatted_results = {
                "total": results.get('total'),
                "query": query,
                "matches": []
            }
            
            for match in results.get('matches', [])[:limit]:
                formatted_results["matches"].append({
                    "ip": match.get('ip_str'),
                    "port": match.get('port'),
                    "org": match.get('org'),
                    "location": f"{match.get('location', {}).get('country_name', 'Unknown')}, {match.get('location', {}).get('city', 'Unknown')}",
                    "service": match.get('_shodan', {}).get('module'),
                    "product": match.get('product'),
                    "banner": match.get('data', '')[:100]
                })
            
            return formatted_results
            
        except Exception as e:
            return {"error": f"Shodan search failed: {str(e)}"}
    
    def get_my_info(self) -> Dict[str, Any]:
        """Информация об аккаунте Shodan"""
        if not self.api_key:
            return {"error": "API key required"}
        
        try:
            info = self.api.info()
            return {
                "plan": info.get('plan'),
                "credits": info.get('credits'),
                "scan_credits": info.get('scan_credits'),
                "usage_limits": info.get('usage_limits', {})
            }
        except Exception as e:
            return {"error": f"Failed to get account info: {str(e)}"}