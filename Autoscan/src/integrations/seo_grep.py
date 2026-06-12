"""SEO/metadata grep: robots.txt, sitemap, meta-теги."""

from __future__ import annotations

import re
from typing import Any, Dict, List
import requests
from bs4 import BeautifulSoup


class SeoGrep:
    def gather(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"source": "seo_grep", "domain": domain}
        for scheme in ("https", "http"):
            base = f"{scheme}://{domain}"
            try:
                robots = self._fetch_text(f"{base}/robots.txt")
                if robots:
                    result["robots_txt"] = {
                        "url": f"{base}/robots.txt",
                        "paths": self._extract_paths(robots),
                        "snippet": robots[:500],
                    }
                sitemap = self._fetch_text(f"{base}/sitemap.xml")
                if sitemap:
                    result["sitemap"] = {
                        "url": f"{base}/sitemap.xml",
                        "urls": re.findall(r"<loc>(.*?)</loc>", sitemap)[:20],
                    }
                meta = self._fetch_meta(base)
                if meta:
                    result["meta"] = meta
                if result.get("robots_txt") or result.get("sitemap") or result.get("meta"):
                    result["base_url"] = base
                    break
            except requests.RequestException:
                continue
        return result

    def _fetch_text(self, url: str) -> str:
        response = requests.get(url, timeout=8, headers={"User-Agent": "ReconScope/0.2"})
        if response.status_code == 200 and response.text.strip():
            return response.text
        return ""

    def _extract_paths(self, robots: str) -> List[str]:
        paths: List[str] = []
        for line in robots.splitlines():
            line = line.strip()
            if line.lower().startswith(("allow:", "disallow:")):
                _, _, path = line.partition(":")
                path = path.strip()
                if path and path != "/":
                    paths.append(path)
        return paths[:30]

    def _fetch_meta(self, base_url: str) -> Dict[str, str]:
        response = requests.get(base_url, timeout=8, headers={"User-Agent": "ReconScope/0.2"})
        if response.status_code != 200:
            return {}
        soup = BeautifulSoup(response.text[:200_000], "lxml")
        meta: Dict[str, str] = {}
        title = soup.find("title")
        if title and title.string:
            meta["title"] = title.string.strip()
        for tag in soup.find_all("meta"):
            name = (tag.get("name") or tag.get("property") or "").lower()
            content = tag.get("content")
            if name in ("description", "keywords", "generator", "og:title", "og:description") and content:
                meta[name] = content.strip()
        return meta
