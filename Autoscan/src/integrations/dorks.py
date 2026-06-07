"""Google и Shodan dorks: генерация запросов и поиск."""

from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = "ReconScope/0.2 (OSINT research)"

GOOGLE_DORK_TEMPLATES: List[tuple[str, str]] = [
    ("site_files", 'site:{d} (ext:env | ext:sql | ext:bak | ext:log | ext:cfg | ext:ini)'),
    ("index_of", 'site:{d} intitle:"index of"'),
    ("login_pages", 'site:{d} (inurl:login | inurl:admin | intitle:"login" | intitle:"dashboard")'),
    ("secrets", 'site:{d} ("api_key" | "apikey" | "password" | "secret" | "token" | "AWS_SECRET")'),
    ("exposed_docs", 'site:{d} (ext:pdf | ext:doc | ext:xls | ext:csv)'),
    ("phpinfo", 'site:{d} (inurl:phpinfo | "PHP Version")'),
    ("git_exposed", 'site:{d} (inurl:.git | "index of" ".git")'),
]

SHODAN_DORK_TEMPLATES: List[tuple[str, str]] = [
    ("hostname", 'hostname:"{d}"'),
    ("ssl_cn", 'ssl.cert.subject.cn:"{d}"'),
    ("http_html", 'http.html:"{d}"'),
    ("org_ssl", 'ssl:"{d}"'),
]


class DorkScanner:
    """Генерация и выполнение Google/Shodan dorks."""

    def __init__(self, shodan_client=None, timeout: float = 12.0):
        self.shodan = shodan_client
        self.timeout = timeout
        self.google_api_key = os.getenv("GOOGLE_API_KEY")
        self.google_cse_id = os.getenv("GOOGLE_CSE_ID")

    def scan(
        self,
        target: str,
        *,
        target_type: str = "domain",
        custom_google: Optional[str] = None,
        custom_shodan: Optional[str] = None,
        full_profile: bool = False,
    ) -> Dict[str, Any]:
        domain = self._normalize_domain(target)
        result: Dict[str, Any] = {
            "source": "dork_scanner",
            "target": target,
            "target_type": target_type,
        }

        if target_type == "domain" and domain:
            google_queries = self._build_google_queries(domain, custom_google, full_profile)
            result["google_dorks"] = self._run_google_dorks(google_queries, full_profile)

        if self.shodan:
            shodan_queries = self._build_shodan_queries(
                target, target_type, domain, custom_shodan, full_profile
            )
            result["shodan_dorks"] = self._run_shodan_dorks(shodan_queries, full_profile)

        google_hits = len(result.get("google_dorks", {}).get("results", []))
        shodan_hits = sum(
            len(block.get("matches", []))
            for block in result.get("shodan_dorks", {}).get("by_query", [])
        )
        result["total_hits"] = google_hits + shodan_hits
        return result

    def _build_google_queries(
        self,
        domain: str,
        custom: Optional[str],
        full: bool,
    ) -> List[Dict[str, str]]:
        queries: List[Dict[str, str]] = []
        if custom:
            queries.append({"id": "custom", "query": custom.strip()})
        limit = len(GOOGLE_DORK_TEMPLATES) if full else 3
        for dork_id, template in GOOGLE_DORK_TEMPLATES[:limit]:
            queries.append({"id": dork_id, "query": template.format(d=domain)})
        return queries

    def _build_shodan_queries(
        self,
        target: str,
        target_type: str,
        domain: str,
        custom: Optional[str],
        full: bool,
    ) -> List[Dict[str, str]]:
        queries: List[Dict[str, str]] = []
        if custom:
            queries.append({"id": "custom", "query": custom.strip()})
        if target_type == "domain" and domain:
            limit = len(SHODAN_DORK_TEMPLATES) if full else 2
            for dork_id, template in SHODAN_DORK_TEMPLATES[:limit]:
                q = template.format(d=domain)
                if not any(item["query"] == q for item in queries):
                    queries.append({"id": dork_id, "query": q})
        elif target_type == "ip":
            queries.append({"id": "ip", "query": f"ip:{target}"})
        return queries

    def _run_google_dorks(
        self,
        queries: List[Dict[str, str]],
        full: bool,
    ) -> Dict[str, Any]:
        max_queries = len(queries) if full else min(3, len(queries))
        per_query = 5 if full else 3
        engine = "none"
        all_results: List[Dict[str, Any]] = []

        for item in queries[:max_queries]:
            query = item["query"]
            hits, used_engine = self._search_web(query, per_query)
            if used_engine != "none":
                engine = used_engine
            for hit in hits:
                all_results.append({**hit, "dork_id": item["id"], "query": query})
            time.sleep(0.4)

        return {
            "engine": engine,
            "queries": queries,
            "results": all_results,
            "count": len(all_results),
        }

    def _run_shodan_dorks(
        self,
        queries: List[Dict[str, str]],
        full: bool,
    ) -> Dict[str, Any]:
        if not self.shodan or not self.shodan.api_key:
            return {
                "engine": "shodan",
                "note": "SHODAN_API_KEY не задан",
                "queries": queries,
                "by_query": [],
                "count": 0,
            }

        max_queries = len(queries) if full else min(2, len(queries))
        by_query: List[Dict[str, Any]] = []
        total = 0

        for item in queries[:max_queries]:
            search = self.shodan.search(item["query"], limit=8 if full else 5)
            matches = search.get("matches", []) if isinstance(search, dict) else []
            if search.get("error"):
                by_query.append({
                    "dork_id": item["id"],
                    "query": item["query"],
                    "error": search["error"],
                    "matches": [],
                })
                continue
            by_query.append({
                "dork_id": item["id"],
                "query": item["query"],
                "total": search.get("total"),
                "matches": matches,
            })
            total += len(matches)

        return {
            "engine": "shodan",
            "queries": queries,
            "by_query": by_query,
            "count": total,
        }

    def _search_web(self, query: str, limit: int) -> tuple[List[Dict[str, Any]], str]:
        if self.google_api_key and self.google_cse_id:
            hits = self._search_google_cse(query, limit)
            if hits:
                return hits, "google_cse"
        hits = self._search_duckduckgo(query, limit)
        return hits, "duckduckgo" if hits else "none"

    def _search_google_cse(self, query: str, limit: int) -> List[Dict[str, Any]]:
        try:
            response = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params={
                    "key": self.google_api_key,
                    "cx": self.google_cse_id,
                    "q": query,
                    "num": min(limit, 10),
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException:
            return []

        results: List[Dict[str, Any]] = []
        for item in data.get("items", [])[:limit]:
            results.append({
                "title": item.get("title"),
                "url": item.get("link"),
                "snippet": (item.get("snippet") or "")[:300],
            })
        return results

    def _search_duckduckgo(self, query: str, limit: int) -> List[Dict[str, Any]]:
        try:
            response = requests.post(
                "https://html.duckduckgo.com/html/",
                data={"q": query, "b": ""},
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException:
            return []

        soup = BeautifulSoup(response.text, "lxml")
        results: List[Dict[str, Any]] = []

        for block in soup.select(".result"):
            link = block.select_one("a.result__a")
            snippet = block.select_one(".result__snippet")
            if not link:
                continue
            url = self._unwrap_ddg_url(link.get("href", ""))
            if not url:
                continue
            results.append({
                "title": link.get_text(strip=True),
                "url": url,
                "snippet": snippet.get_text(strip=True)[:300] if snippet else "",
            })
            if len(results) >= limit:
                break
        return results

    def _unwrap_ddg_url(self, href: str) -> str:
        if not href:
            return ""
        if href.startswith("//duckduckgo.com/l/?"):
            href = "https:" + href
        if "uddg=" in href:
            parsed = urlparse(href)
            params = parse_qs(parsed.query)
            uddg = params.get("uddg", [""])[0]
            return unquote(uddg)
        return href

    def _normalize_domain(self, target: str) -> str:
        target = target.strip().lower()
        if target.startswith("http"):
            target = urlparse(target).netloc
        return target.rstrip(".")
