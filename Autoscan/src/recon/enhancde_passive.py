from __future__ import annotations

import asyncio
import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from src.core.contracts import IntelligenceProvider
from src.core.events import BaseEvent
from src.integrations.dorks import DorkScanner, enrich_shodan_dorks_from_hosts
from src.integrations.file_enum import FileEnumerator
from src.integrations.github_osint import GitHubOSINT
from src.integrations.nmap import NmapScanner
from src.integrations.seo_grep import SeoGrep
from src.integrations.shodan import ShodanClient
from src.integrations.subdomain import SubdomainEnumerator
from src.integrations.tech_detect import TechnologyDetector
from src.integrations.threat_intel import aggregate_intel
from src.integrations.virustotal import VirusTotalClient
from src.recon.cache import get_cached, set_cached
from src.recon.options import ReconOptions
from src.recon.osint_utils import collect_unique_ips, derive_subnets, resolve_hosts
from src.recon.reporting import build_action_summary, build_markdown_report, build_text_summary


class EnhancedPassiveRecon(IntelligenceProvider):
    """OSINT-????????: ??????????, IP, ????????, ????????????, ???????, GitHub, TI."""

    def __init__(
        self,
        shodan: Optional[ShodanClient] = None,
        vt: Optional[VirusTotalClient] = None,
        nmap: Optional[NmapScanner] = None,
    ):
        self.shodan = shodan or ShodanClient(os.getenv("SHODAN_API_KEY"))
        self.vt = vt or VirusTotalClient(os.getenv("VIRUSTOTAL_API_KEY"))
        self.nmap = nmap or NmapScanner()
        self.subdomains = SubdomainEnumerator()
        self.tech = TechnologyDetector()
        self.files = FileEnumerator()
        self.github = GitHubOSINT()
        self.seo = SeoGrep()
        self.dorks = DorkScanner(shodan_client=self.shodan)

    @property
    def provider_name(self) -> str:
        return "enhanced_passive_recon"

    def gather(
        self,
        target: str,
        target_type: str = "ip",
        options: Optional[ReconOptions] = None,
    ) -> Dict[str, Any]:
        options = options or ReconOptions()
        if not self._validate_target(target, target_type):
            return {"error": f"Invalid target: {target} for type: {target_type}"}

        if options.use_cache:
            cached = get_cached(target, target_type, options.profile, options.scanners)
            if cached:
                return cached

        results: Dict[str, Any] = {
            "target": target,
            "target_type": target_type,
            "profile": options.profile,
            "module": "recon",
        }

        scan_hosts: List[str] = [target]

        # --- 1. ???????????, IP, ???????? ---
        if target_type == "domain" and options.scanners.get("subdomains", True):
            sub_data = self.subdomains.enumerate(target, brute=True)
            if options.scanners.get("shodan", True):
                shodan_dns = self.shodan.dns_domain(target)
                if shodan_dns.get("subdomains"):
                    hosts_set = set(sub_data.get("hosts", [target]))
                    sources = dict(sub_data.get("sources") or {})
                    shodan_hosts: List[str] = []
                    for label in shodan_dns["subdomains"]:
                        fqdn = label if label.endswith(target) else f"{label}.{target}"
                        shodan_hosts.append(fqdn)
                        hosts_set.add(fqdn)
                    sources["shodan_dns"] = len(shodan_hosts)
                    ordered = sorted(hosts_set)
                    sub_data["hosts"] = ordered
                    sub_data["count"] = len(ordered)
                    sub_data["sources"] = sources
                if shodan_dns and not shodan_dns.get("error"):
                    results["shodan_dns"] = shodan_dns
            results["subdomains"] = sub_data
            scan_hosts = sub_data.get("hosts", [target])

            host_limit = 30 if options.is_full else 15
            resolved = resolve_hosts(scan_hosts[:host_limit])
            results["dns_resolution"] = resolved
            results["resolved_ips"] = collect_unique_ips(resolved)
            results["subnets"] = derive_subnets(results["resolved_ips"])

        if target_type == "ip":
            results["resolved_ips"] = [target]
            results["subnets"] = derive_subnets([target])

        # --- 2. ??????????? ??????? (?????????????) ---
        passive_tasks: Dict[str, Callable[[], Any]] = {}

        if options.scanners.get("github", True):
            passive_tasks["github_leaks"] = lambda: self.github.search_snippets(target)

        if target_type == "domain" and options.scanners.get("seo", True):
            passive_tasks["seo"] = lambda: self.seo.gather(target)

        if target_type == "domain" and options.scanners.get("technologies", True):
            max_hosts = 10 if options.is_full else 5
            passive_tasks["technologies"] = lambda: self.tech.scan(
                scan_hosts, max_hosts=max_hosts
            )

        if target_type == "domain" and options.scanners.get("files", True):
            file_hosts_limit = 8 if options.is_full else 4
            paths_limit = 12 if options.is_full else 10
            passive_tasks["files"] = lambda: self.files.enumerate_hosts(
                scan_hosts,
                max_hosts=file_hosts_limit,
                max_paths=paths_limit,
            )

        if options.scanners.get("virustotal", True):
            if target_type == "domain":
                passive_tasks["virustotal"] = lambda: self.vt.get_domain_info(target)
            elif target_type == "ip":
                passive_tasks["virustotal"] = lambda: self.vt.get_ip_info(target)

        if options.scanners.get("dorks", True) and target_type in ("domain", "ip"):
            passive_tasks["dorks"] = lambda: self.dorks.scan(
                target,
                target_type=target_type,
                custom_google=options.overrides.get("google_dork"),
                custom_shodan=options.overrides.get("shodan_query"),
                full_profile=options.is_full,
            )
        elif options.scanners.get("shodan", True):
            shodan_query = options.overrides.get("shodan_query")
            if shodan_query:
                passive_tasks["shodan_search"] = lambda: self.shodan.search(
                    shodan_query, limit=15
                )
            elif target_type == "domain":
                default_query = f'hostname:"{target}"'
                passive_tasks["shodan_search"] = lambda: self.shodan.search(
                    default_query, limit=10
                )

        passive_results = self._run_parallel(passive_tasks)
        for key, value in passive_results.items():
            if value and (not isinstance(value, dict) or "error" not in value):
                results[key] = value

        # --- 3. Nmap (??????????, ??????????) ---
        if options.scanners.get("nmap", True):
            nmap_args = options.overrides.get("nmap_args")
            if nmap_args:
                nmap_result = self._run_async(self.nmap.scan_target(target, nmap_args))
            elif options.is_full:
                nmap_result = self._run_async(self.nmap.full_scan(target))
            else:
                nmap_result = self._run_async(self.nmap.quick_scan(target))
            if "error" not in nmap_result:
                results["network_scan"] = nmap_result

        # --- 4. Shodan ?? IP (?????????????) ---
        if options.scanners.get("shodan", True):
            ips = results.get("resolved_ips", [])[:5]

            def _host_intel(ip: str) -> Dict[str, Any]:
                return self.shodan.get_host(ip)

            host_tasks = {f"shodan_{ip}": (lambda i=ip: _host_intel(i)) for ip in ips}
            for _, intel in self._run_parallel(host_tasks).items():
                if isinstance(intel, dict) and "error" not in intel:
                    results.setdefault("shodan_hosts", []).append(intel)

        if results.get("dorks") and results.get("shodan_hosts"):
            results["dorks"] = enrich_shodan_dorks_from_hosts(
                results["dorks"],
                results["shodan_hosts"],
                target,
            )

        # --- 5. Network discovery ---
        if target_type == "network":
            network_scan = self._run_async(self.nmap.scan_target(target, "-sn"))
            if "error" not in network_scan:
                results["network_discovery"] = network_scan

        # --- 6. Threat intelligence + ???????????????? ---
        results["threat_intel"] = aggregate_intel(results)
        results["summary"] = build_text_summary(results)
        results["action_summary"] = build_action_summary(results)

        if options.use_cache:
            cache_key = set_cached(target, target_type, options.profile, options.scanners, results)
            results["cache_key"] = cache_key

        return results

    def comprehensive_scan(
        self,
        target: str,
        target_type: str = "ip",
        options: Optional[ReconOptions] = None,
    ) -> BaseEvent:
        opts = options or ReconOptions.from_request(comprehensive=True)
        intelligence = self.gather(target, target_type, opts)
        event_id = f"comprehensive_{target_type}_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        intelligence["report_markdown"] = build_markdown_report(
            target, target_type, intelligence, event_id=event_id
        )
        return BaseEvent(
            event_id=event_id,
            event_type="comprehensive_recon",
            source=self.provider_name,
            data=intelligence,
        )

    def _run_parallel(self, tasks: Dict[str, Callable[[], Any]]) -> Dict[str, Any]:
        if not tasks:
            return {}
        results: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=min(6, len(tasks))) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as exc:  # noqa: BLE001
                    results[name] = {"error": str(exc)}
        return results

    def _validate_target(self, target: str, target_type: str) -> bool:
        try:
            if target_type == "ip":
                ipaddress.ip_address(target)
                return True
            if target_type == "domain":
                return len(target) > 0 and "." in target
            if target_type == "network":
                ipaddress.ip_network(target, strict=False)
                return True
            return False
        except ValueError:
            return False

    def _run_async(self, coro):
        return asyncio.run(coro)
