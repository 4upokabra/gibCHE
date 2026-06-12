"""Определение технологий по HTTP-заголовкам и HTML."""

from __future__ import annotations

from typing import Any, Dict, List, Set

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 8.0


class TechnologyDetector:
    def scan(self, target: str, max_hosts: int = 5) -> Dict[str, Any]:
        hosts = [target] if isinstance(target, str) else list(target)
        results: List[Dict[str, Any]] = []

        for host in hosts[:max_hosts]:
            for scheme in ("https", "http"):
                url = host if host.startswith("http") else f"{scheme}://{host}"
                entry = self._probe(url)
                if entry.get("technologies"):
                    results.append(entry)
                    break

        all_tech: Set[str] = set()
        for item in results:
            all_tech.update(item.get("technologies", []))

        return {
            "source": "tech_detect",
            "scanned": len(results),
            "technologies": sorted(all_tech),
            "hosts": results,
        }

    def _probe(self, url: str) -> Dict[str, Any]:
        technologies: Set[str] = set()
        try:
            response = requests.get(
                url,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "ReconScope/0.2"},
            )
            headers = {k.lower(): v for k, v in response.headers.items()}
            if "server" in headers:
                technologies.add(f"Server: {headers['server']}")
            if "x-powered-by" in headers:
                technologies.add(f"X-Powered-By: {headers['x-powered-by']}")
            if "x-aspnet-version" in headers:
                technologies.add(f"ASP.NET: {headers['x-aspnet-version']}")

            content_type = headers.get("content-type", "")
            if "text/html" in content_type:
                soup = BeautifulSoup(response.text[:500_000], "lxml")
                generator = soup.find("meta", attrs={"name": "generator"})
                if generator and generator.get("content"):
                    technologies.add(f"Generator: {generator['content']}")
                for script in soup.find_all("script", src=True):
                    src = script["src"].lower()
                    for name in ("jquery", "react", "vue", "angular", "bootstrap", "wordpress"):
                        if name in src:
                            technologies.add(name.capitalize())

            return {
                "url": response.url,
                "status_code": response.status_code,
                "technologies": sorted(technologies),
            }
        except requests.RequestException as exc:
            return {"url": url, "error": str(exc), "technologies": []}
