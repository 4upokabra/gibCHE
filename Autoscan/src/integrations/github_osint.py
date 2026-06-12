"""Поиск утечек кода на GitHub (короткие сниппеты)."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

import requests


class GitHubOSINT:
    def __init__(self, token: str | None = None):
        self.token = token or os.getenv("GITHUB_TOKEN")

    def search_snippets(self, keyword: str, limit: int = 5) -> Dict[str, Any]:
        if self.token:
            return self._search_with_token(keyword, limit)
        return self._search_public(keyword, limit)

    def _search_with_token(self, keyword: str, limit: int) -> Dict[str, Any]:
        queries = [
            f'"{keyword}" extension:env',
            f'"{keyword}" password OR api_key OR secret',
            f'"{keyword}" filename:config',
        ]

        snippets: List[Dict[str, Any]] = []
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        for query in queries:
            if len(snippets) >= limit:
                break
            try:
                response = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 3},
                    headers=headers,
                    timeout=15,
                )
                if response.status_code == 403:
                    fallback = self._search_public(keyword, limit - len(snippets))
                    snippets.extend(fallback.get("snippets", []))
                    break
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as exc:
                return {"source": "github", "error": str(exc), "snippets": snippets}

            for item in data.get("items", []):
                if len(snippets) >= limit:
                    break
                snippets.append(self._format_code_item(item, query))

        return {
            "source": "github",
            "keyword": keyword,
            "count": len(snippets),
            "snippets": snippets,
        }

    def _search_public(self, keyword: str, limit: int) -> Dict[str, Any]:
        snippets: List[Dict[str, Any]] = []
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "ReconScope-OSINT",
        }

        for query in (
            f"{keyword} in:file",
            f"{keyword} in:readme,description",
        ):
            if len(snippets) >= limit:
                break
            try:
                response = requests.get(
                    "https://api.github.com/search/repositories",
                    params={"q": query, "per_page": min(3, limit), "sort": "updated"},
                    headers=headers,
                    timeout=15,
                )
                if response.status_code in (403, 422):
                    break
                response.raise_for_status()
                for item in response.json().get("items", []):
                    if len(snippets) >= limit:
                        break
                    snippets.append({
                        "repository": item.get("full_name"),
                        "path": item.get("description") or "repository",
                        "url": item.get("html_url"),
                        "query": query,
                        "note": "Публичный поиск репозиториев (без GITHUB_TOKEN)",
                    })
            except requests.RequestException:
                continue

        if len(snippets) < limit:
            snippets.extend(self._search_grep_app(keyword, limit - len(snippets)))

        note = None
        if not self.token:
            note = (
                "GITHUB_TOKEN не задан — использованы публичные источники. "
                "Для поиска по коду задайте PAT: github.com/settings/tokens"
            )

        return {
            "source": "github",
            "keyword": keyword,
            "count": len(snippets),
            "snippets": snippets[:limit],
            "note": note,
        }

    def _search_grep_app(self, keyword: str, limit: int) -> List[Dict[str, Any]]:
        if limit <= 0:
            return []
        snippets: List[Dict[str, Any]] = []
        try:
            response = requests.get(
                "https://grep.app/api/search",
                params={"q": keyword, "regexp": "false"},
                headers={"User-Agent": "ReconScope-OSINT"},
                timeout=15,
            )
            if response.status_code != 200:
                return []
            payload = response.json()
        except (requests.RequestException, ValueError):
            return []

        for hit in (payload.get("hits") or {}).get("hits", [])[:limit]:
            repo = hit.get("repo", {})
            path = hit.get("path", {})
            raw = (hit.get("content") or {}).get("snippet", "")
            snippet_text = re.sub(r"\s+", " ", raw).strip()[:240]
            snippets.append({
                "repository": repo.get("raw"),
                "path": path.get("raw"),
                "url": f"https://grep.app/search?q={keyword}",
                "query": f"grep.app:{keyword}",
                "snippet": snippet_text,
                "note": "grep.app (публичный поиск фрагментов кода)",
            })
        return snippets

    @staticmethod
    def _format_code_item(item: Dict[str, Any], query: str) -> Dict[str, Any]:
        return {
            "repository": item.get("repository", {}).get("full_name"),
            "path": item.get("path"),
            "url": item.get("html_url"),
            "query": query,
        }
