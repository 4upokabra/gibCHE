import asyncio
import logging
import sys
from pathlib import Path

# Добавляем корень проекта в sys.path, чтобы можно было импортировать пакет llm
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from llm.pipeline import LLMScannerPipeline, ScanOptions

logging.basicConfig(level=logging.INFO)


async def main() -> None:
    pipeline = LLMScannerPipeline()
    try:
        report = await pipeline.run(
            url="http://62.173.140.174:16093/",
            scan_goal=(
                "Комплексный аудит безопасности: ищи OWASP Top 10, инъекции, "
                "уязвимости конфигурации, слабые заголовки, утечки данных, "
                "уязвимости аутентификации и авторизации."
            ),
            options=ScanOptions(use_browser=True),
        )
    finally:
        await pipeline.aclose()

    print("=== SUMMARY ===")
    print(report.summary)
    print("\n=== FINDINGS ===")
    for finding in report.findings:
        print(f"- {finding.severity.upper()}: {finding.title}")
        if finding.description:
            print(f"  {finding.description}")
        if finding.cwe_ids:
            print(f"  CWE: {', '.join(finding.cwe_ids)}")
        if finding.cve_ids:
            print(f"  CVE: {', '.join(finding.cve_ids)}")
        if finding.bdu_ids:
            print(f"  БДУ ФСТЭК: {', '.join(finding.bdu_ids)}")
        if finding.threat_ids:
            print(f"  Угрозы (УБИ): {', '.join(finding.threat_ids)}")
        if finding.recommendations:
            print("  Recommendations:")
            for rec in finding.recommendations:
                print(f"    * {rec}")


if __name__ == "__main__":
    asyncio.run(main())

