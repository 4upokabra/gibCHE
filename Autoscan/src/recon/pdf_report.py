"""Генерация PDF-отчётов по разведке."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fpdf import FPDF

from src.recon.reporting import build_markdown_report, build_text_summary


class ReconPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "ReconScope - Otchyot razvedki", ln=True, align="C")
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


def _safe_text(value: Any, limit: int = 500) -> str:
    text = str(value or "")
    text = text.encode("latin-1", errors="replace").decode("latin-1")
    return text[:limit]


def build_pdf_report(
    target: str,
    target_type: str,
    data: Dict[str, Any],
    *,
    event_id: Optional[str] = None,
    llm_summary: Optional[str] = None,
) -> bytes:
    pdf = ReconPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _safe_text(f"Tsel: {target}"), ln=True)
    pdf.set_font("Helvetica", size=10)
    if event_id:
        pdf.cell(0, 6, _safe_text(f"ID: {event_id}"), ln=True)
    pdf.cell(0, 6, _safe_text(f"Tip: {target_type} | Profil: {data.get('profile', 'quick')}"), ln=True)
    if data.get("from_cache"):
        pdf.cell(0, 6, "Istochnik: kesh", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Svodka", ln=True)
    pdf.set_font("Helvetica", size=10)
    pdf.multi_cell(0, 5, _safe_text(build_text_summary(data), 2000))
    pdf.ln(3)

    sections = [
        ("Poddomeny", data.get("subdomains", {}).get("hosts", [])),
        ("IP-adresa", data.get("resolved_ips", [])),
        ("Podseti", data.get("subnets", [])),
        ("Tekhnologii", data.get("technologies", {}).get("technologies", [])),
    ]
    for title, items in sections:
        if not items:
            continue
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _safe_text(f"{title} ({len(items)})"), ln=True)
        pdf.set_font("Helvetica", size=9)
        for item in items[:30]:
            pdf.multi_cell(0, 4, _safe_text(f"  - {item}"))
        if len(items) > 30:
            pdf.cell(0, 4, _safe_text(f"  ... i eshche {len(items) - 30}"), ln=True)
        pdf.ln(2)

    files = data.get("files", {}).get("found", [])
    if files:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _safe_text(f"Fajly ({len(files)})"), ln=True)
        pdf.set_font("Helvetica", size=9)
        for item in files[:25]:
            pdf.multi_cell(0, 4, _safe_text(f"  [{item.get('status')}] {item.get('url')}"))
        pdf.ln(2)

    dorks = data.get("dorks", {})
    google = dorks.get("google_dorks", {}).get("results", [])
    if google:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _safe_text(f"Google dorks ({len(google)})"), ln=True)
        pdf.set_font("Helvetica", size=9)
        for hit in google[:15]:
            pdf.multi_cell(0, 4, _safe_text(f"  {hit.get('url')}"))
        pdf.ln(2)

    shodan_blocks = dorks.get("shodan_dorks", {}).get("by_query", [])
    if shodan_blocks:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Shodan dorks", ln=True)
        pdf.set_font("Helvetica", size=9)
        for block in shodan_blocks[:8]:
            pdf.multi_cell(0, 4, _safe_text(f"  Q: {block.get('query')}"))
            for match in block.get("matches", [])[:5]:
                pdf.multi_cell(
                    0, 4, _safe_text(f"    {match.get('ip')}:{match.get('port')}")
                )
        pdf.ln(2)

    leaks = data.get("github_leaks", {}).get("snippets", [])
    if leaks:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _safe_text(f"GitHub ({len(leaks)})"), ln=True)
        pdf.set_font("Helvetica", size=9)
        for item in leaks[:15]:
            pdf.multi_cell(
                0, 4, _safe_text(f"  {item.get('repository')}/{item.get('path')}")
            )
        pdf.ln(2)

    ti = data.get("threat_intel", {})
    if ti.get("findings"):
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _safe_text(f"Threat Intel (score: {ti.get('risk_score', 0)})"), ln=True)
        pdf.set_font("Helvetica", size=9)
        for finding in ti["findings"][:15]:
            pdf.multi_cell(0, 4, _safe_text(f"  [{finding.get('type')}] {finding}"))
        pdf.ln(2)

    actions = data.get("action_summary", {})
    if actions:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Rekomendacii", ln=True)
        pdf.set_font("Helvetica", size=9)
        for item in actions.get("defensive_actions", []):
            pdf.multi_cell(0, 4, _safe_text(f"  [DEF] {item}"))
        for item in actions.get("offensive_actions", []):
            pdf.multi_cell(0, 4, _safe_text(f"  [OFF] {item}"))
        pdf.ln(2)

    if llm_summary:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "LLM audit", ln=True)
        pdf.set_font("Helvetica", size=9)
        pdf.multi_cell(0, 4, _safe_text(llm_summary, 3000))

    raw = pdf.output(dest="S")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return str(raw).encode("latin-1")
