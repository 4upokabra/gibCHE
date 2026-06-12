import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any
import asyncio

class NmapScanner:
    def __init__(self):
        # В Docker nmap уже установлен и доступен
        self.nmap_path = "nmap"

    @staticmethod
    def _with_skip_ping(arguments: str) -> str:
        """Многие публичные хосты не отвечают на ping — без -Pn nmap вернёт пустой отчёт."""
        if "-Pn" in arguments or "-sn" in arguments:
            return arguments
        return f"-Pn {arguments}"

    async def scan_target(self, target: str, arguments: str = "-sS -sV") -> Dict[str, Any]:
        """Асинхронное сканирование через Nmap"""
        try:
            nmap_args = self._with_skip_ping(arguments)
            cmd = f"{self.nmap_path} {nmap_args} -oX - {target}"
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return {
                    "error": f"Nmap failed: {stderr.decode()}",
                    "target": target
                }
            
            # Парсим XML результат
            return self._parse_nmap_xml(stdout.decode(), target, nmap_args)
            
        except Exception as e:
            return {"error": f"Nmap scan failed: {str(e)}"}
    
    def _parse_nmap_xml(self, xml_output: str, target: str, arguments: str) -> Dict[str, Any]:
        """Парсит XML вывод Nmap"""
        try:
            if not xml_output.strip():
                return {"error": "Empty Nmap output"}
            
            root = ET.fromstring(xml_output)
            
            result = {
                "source": "nmap",
                "target": target,
                "arguments": arguments,
                "hosts": {}
            }
            
            # Обрабатываем каждый хост
            for host in root.findall("host"):
                host_info = self._parse_host(host)
                if host_info:
                    ip = host_info.get("ip", "unknown")
                    result["hosts"][ip] = host_info
            
            return result
            
        except Exception as e:
            return {"error": f"XML parsing failed: {str(e)}"}
    
    def _parse_host(self, host_element) -> Dict[str, Any]:
        """Парсит информацию о хосте"""
        try:
            # IP адрес
            address = host_element.find("address")
            if address is None:
                return {}
            
            ip = address.get("addr", "")
            
            # Статус
            status = host_element.find("status")
            state = status.get("state", "unknown") if status else "unknown"
            
            # Порты
            ports = []
            for port_elem in host_element.findall("ports/port"):
                port_info = {
                    "port": port_elem.get("portid"),
                    "protocol": port_elem.get("protocol"),
                    "state": "unknown"
                }
                
                state_elem = port_elem.find("state")
                if state_elem is not None:
                    port_info["state"] = state_elem.get("state", "unknown")
                
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    port_info["service"] = service_elem.get("name", "unknown")
                    port_info["version"] = service_elem.get("version", "")
                
                ports.append(port_info)
            
            return {
                "ip": ip,
                "status": state,
                "ports": ports
            }
            
        except Exception as e:
            return {"error": f"Host parsing error: {str(e)}"}
    
    async def quick_scan(self, target: str) -> Dict[str, Any]:
        """Быстрое сканирование"""
        return await self.scan_target(target, "-F -T4")
    
    async def full_scan(self, target: str) -> Dict[str, Any]:
        """Полное сканирование (top-1000 портов — баланс скорости и полноты)."""
        return await self.scan_target(target, "--top-ports 1000 -sV -T4")