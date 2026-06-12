"""
Пакет компонентов LLM-сканера.

Содержит модульные этапы пайплайна:
- загрузка страниц (`fetchers`);
- очистка и структурирование (`processing`);
- формирование промптов и вызов моделей (`llm_client`, `prompts`);
- пост-обработка результатов (`postprocessing`);
- orchestration (`pipeline`).
"""

from . import models, fetchers, processing, prompts, llm_client, postprocessing, pipeline

__all__ = [
    "models",
    "fetchers",
    "processing",
    "prompts",
    "llm_client",
    "postprocessing",
    "pipeline",
]

