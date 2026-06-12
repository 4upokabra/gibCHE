"""Нормализация threat intelligence из результатов разведки."""

from __future__ import annotations

from typing import Any, Dict, List, Set


def aggregate_intel(recon_data: Dict[str, Any]) -> Dict[str, Any]:
    """Собирает IOC, CVE и риски из сырых данных recon."""
    findings: List[Dict[str, Any]] = []
    iocs: Set[str] = set()
    cves: Set[str] = set()

    shodan = recon_data.get("shodan", {})
    shodan_data = shodan.get("data", shodan) if isinstance(shodan, dict) else {}
    for vuln in shodan_data.get("vulnerabilities", []) or []:
        cves.add(str(vuln))
        findings.append({"type": "cve", "source": "shodan", "value": str(vuln), "severity": "unknown"})

    dorks = recon_data.get("dorks", {})
    for hit in dorks.get("google_dorks", {}).get("results", []) or []:
        url = hit.get("url")
        if url:
            findings.append({
                "type": "google_dork",
                "source": "dork_scanner",
                "url": url,
                "title": hit.get("title"),
                "query": hit.get("query"),
            })
    for block in dorks.get("shodan_dorks", {}).get("by_query", []) or []:
        for match in block.get("matches", []) or []:
            ip = match.get("ip")
            if ip:
                iocs.add(ip)
            findings.append({
                "type": "shodan_dork",
                "source": "dork_scanner",
                "query": block.get("query"),
                "ip": match.get("ip"),
                "port": match.get("port"),
                "product": match.get("product"),
            })

    for match in recon_data.get("shodan_search", {}).get("matches", []) or []:
        ip = match.get("ip")
        if ip:
            iocs.add(ip)
            findings.append({
                "type": "exposed_service",
                "source": "shodan_search",
                "ip": ip,
                "port": match.get("port"),
                "product": match.get("product"),
            })

    vt = recon_data.get("virustotal", {})
    vt_data = vt.get("data", {}) if isinstance(vt, dict) else {}
    attrs = vt_data.get("data", {}).get("attributes", {}) if isinstance(vt_data, dict) else {}
    stats = attrs.get("last_analysis_stats", {})
    if stats.get("malicious", 0) > 0:
        findings.append({
            "type": "reputation",
            "source": "virustotal",
            "malicious": stats["malicious"],
            "suspicious": stats.get("suspicious", 0),
        })

    for item in recon_data.get("github_leaks", {}).get("snippets", []) or []:
        findings.append({
            "type": "code_leak",
            "source": "github",
            "repository": item.get("repository"),
            "path": item.get("path"),
            "url": item.get("url"),
        })

    for item in recon_data.get("files", {}).get("found", []) or []:
        if item.get("status") == 200:
            findings.append({
                "type": "exposed_file",
                "source": "file_enum",
                "url": item.get("url"),
                "severity": "high" if ".env" in (item.get("url") or "") else "medium",
            })

    risk_score = min(100, len(findings) * 8 + len(cves) * 5)

    return {
        "source": "threat_intel",
        "risk_score": risk_score,
        "findings_count": len(findings),
        "cves": sorted(cves),
        "iocs": sorted(iocs),
        "findings": findings,
    }
