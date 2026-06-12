"""Пассивное перечисление поддоменов (crt.sh + DNS)."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Set

import requests

from src.recon.osint_utils import dedupe_sorted, normalize_domain

logger = logging.getLogger(__name__)

# Небольшой встроенный wordlist для активной проверки (quick-профиль пропускает)
COMMON_PREFIXES = (
    "www", "mail", "ftp", "api", "dev", "staging", "stage", "test",
    "admin", "portal", "vpn", "cdn", "static", "app", "beta", "m",
)


class SubdomainEnumerator:
    """Сбор поддоменов через Certificate Transparency и DNS-брут."""

    def __init__(self, timeout: float = 25.0):
        self.timeout = timeout

    def enumerate(self, domain: str, brute: bool = False) -> Dict[str, Any]:
        domain = normalize_domain(domain)
        if not domain or "." not in domain:
            return {"error": f"Invalid domain: {domain}", "hosts": []}

        sources: Dict[str, List[str]] = {}
        hosts: Set[str] = {domain}

        crt_hosts = self._fetch_crtsh(domain)
        if crt_hosts:
            sources["crtsh"] = crt_hosts
            hosts.update(crt_hosts)

        if brute:
            brute_hosts = self._brute_common(domain)
            if brute_hosts:
                sources["dns_brute"] = brute_hosts
                hosts.update(brute_hosts)

        ordered = dedupe_sorted(hosts)
        return {
            "source": "subdomain_enumerator",
            "domain": domain,
            "count": len(ordered),
            "hosts": ordered,
            "sources": {k: len(v) for k, v in sources.items()},
        }

    def _fetch_crtsh(self, domain: str) -> List[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            entries = response.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
            logger.warning("crt.sh lookup failed for %s: %s", domain, exc)
            return []

        found: Set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for line in name_value.splitlines():
                candidate = normalize_domain(line.replace("*.", ""))
                if candidate.endswith(f".{domain}") or candidate == domain:
                    if " " not in candidate and len(candidate) <= 253:
                        found.add(candidate)
        return dedupe_sorted(found)

    def _brute_common(self, domain: str) -> List[str]:
        found: List[str] = []
        for prefix in COMMON_PREFIXES:
            host = f"{prefix}.{domain}"
            try:
                import socket

                socket.getaddrinfo(host, None)
                found.append(host)
            except OSError:
                continue
        return dedupe_sorted(found)
