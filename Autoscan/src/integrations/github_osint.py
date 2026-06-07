"""Поиск утечек кода на GitHub (короткие сниппеты)."""

from __future__ import annotations

import os
from typing import Any, Dict, List

import requests


class GitHubOSINT:
    def __init__(self, token: str | None = None):
        self.token = token or os.getenv("GITHUB_TOKEN")

    def search_snippets(self, keyword: str, limit: int = 5) -> Dict[str, Any]:
        if not self.token:
            return {
                "source": "github",
                "keyword": keyword,
                "note": "GITHUB_TOKEN не задан. Создайте PAT на github.com/settings/tokens",
                "snippets": [],
            }

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
                    return {
                        "source": "github",
                        "error": "GitHub API rate limit или нет доступа",
                        "snippets": snippets,
                    }
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as exc:
                return {"source": "github", "error": str(exc), "snippets": snippets}

            for item in data.get("items", []):
                if len(snippets) >= limit:
                    break
                snippets.append({
                    "repository": item.get("repository", {}).get("full_name"),
                    "path": item.get("path"),
                    "url": item.get("html_url"),
                    "query": query,
                })

        return {
            "source": "github",
            "keyword": keyword,
            "count": len(snippets),
            "snippets": snippets,
        }
