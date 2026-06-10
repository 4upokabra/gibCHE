import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

AUTOSCAN_DIR = ROOT / "Autoscan"
if str(AUTOSCAN_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOSCAN_DIR))

from src.attack import AttackOrchestrator, AttackVector, TestingModel  # noqa: E402


def pretty(event) -> str:
    return json.dumps(event.to_dict(), indent=2, ensure_ascii=False)


def main() -> None:
    orchestrator = AttackOrchestrator()

    scenarios = [
        {
            "title": "Dry-run брутфорса (Black Box)",
            "attack_type": AttackVector.BRUTE_FORCE.value,
            "target": "10.10.10.10",
            "profile": TestingModel.BLACK_BOX,
            "parameters": {
                "service": "ssh",
                "port": 22,
                "rate_limit": 4,
            },
            "dry_run": True,
        },
        {
            "title": "SQLi тест (Grey Box)",
            "attack_type": AttackVector.SQLI.value,
            "target": "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "profile": TestingModel.GREY_BOX,
            "parameters": {
                "level": 3,
                "risk": 2,
                "headers": {"User-Agent": "ReconScope"},
            },
            "dry_run": True,
        },
        {
            "title": "Проверка устаревших версий + автозапуск эксплойта",
            "attack_type": AttackVector.LEGACY_AUDIT.value,
            "target": "vuln-demo.local",
            "profile": TestingModel.WHITE_BOX,
            "parameters": {
                "banners": [
                    "Server: Apache/2.4.49 (Unix)",
                    "X-OWA-Version: 15.0.1497.2",
                ],
                "auto_exploit": True,
                "port": 443,
            },
            "dry_run": True,
        },
    ]

    for scenario in scenarios:
        print(f"\n=== {scenario['title']} ===")
        event = orchestrator.execute_attack(
            scenario["attack_type"],
            scenario["target"],
            parameters=scenario["parameters"],
            profile=scenario["profile"],
            dry_run=scenario["dry_run"],
        )
        print(pretty(event))


if __name__ == "__main__":
    main()

