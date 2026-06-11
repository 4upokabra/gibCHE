"""Проверка типовых путей и файлов на веб-сервере."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set

import requests

COMMON_PATHS = (
    "robots.txt",
    "sitemap.xml",
    ".env",
    ".git/config",
    ".git/HEAD",
    "backup.zip",
    "backup.sql",
    "wp-config.php.bak",
    "config.php.bak",
    "web.config",
    "phpinfo.php",
    "server-status",
    ".well-known/security.txt",
    "crossdomain.xml",
)

USER_AGENT = "ReconScope/0.2"


class FileEnumerator:
    def __init__(self, timeout: float = 5.0, max_workers: int = 6):
        self.timeout = timeout
        self.max_workers = max_workers

    def enumerate(self, target: str, max_paths: int = 12) -> Dict[str, Any]:
        return self.enumerate_hosts([target], max_hosts=1, max_paths=max_paths)

    def enumerate_hosts(
        self,
        hosts: List[str],
        *,
        max_hosts: int = 5,
        max_paths: int = 10,
    ) -> Dict[str, Any]:
        unique_hosts = self._normalize_hosts(hosts, max_hosts)
        if not unique_hosts:
            return {"source": "file_enum", "checked": 0, "found": [], "count": 0, "by_host": {}}

        tasks: List[tuple[str, str, str]] = []
        for host in unique_hosts:
            for scheme in ("https", "http"):
                base = host if host.startswith("http") else f"{scheme}://{host}"
                for path in COMMON_PATHS[:max_paths]:
                    tasks.append((host, base.rstrip("/"), path))

        found: List[Dict[str, Any]] = []
        by_host: Dict[str, List[Dict[str, Any]]] = {}
        checked = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._probe, base, path, host): (host, base, path)
                for host, base, path in tasks
            }
            for future in as_completed(futures):
                checked += 1
                host, _, _ = futures[future]
                result = future.result()
                if result:
                    found.append(result)
                    by_host.setdefault(host, []).append(result)

        return {
            "source": "file_enum",
            "hosts_scanned": unique_hosts,
            "checked": checked,
            "found": found,
            "count": len(found),
            "by_host": by_host,
        }

    def _probe(self, base: str, path: str, host: str) -> Optional[Dict[str, Any]]:
        url = f"{base}/{path}"
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            )
            if response.status_code in (200, 401, 403):
                snippet = response.text[:300].replace("\n", " ").strip()
                return {
                    "host": host,
                    "url": url,
                    "status": response.status_code,
                    "size": len(response.content),
                    "snippet": snippet,
                }
        except requests.RequestException:
            pass
        return None

    def _normalize_hosts(self, hosts: List[str], max_hosts: int) -> List[str]:
        seen: Set[str] = set()
        result: List[str] = []
        for host in hosts:
            h = host.strip().lower().rstrip(".")
            if not h or h in seen:
                continue
            seen.add(h)
            result.append(h)
            if len(result) >= max_hosts:
                break
        return result
