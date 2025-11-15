from abc import ABC, abstractmethod
from typing import Dict, Any, Protocol
from datetime import datetime

class IntelligenceProvider(Protocol):
    """Контракт для провайдеров разведки"""
    
    def gather(self, target: str, target_type: str) -> Dict[str, Any]:
        ...
    
    @property
    def provider_name(self) -> str:
        ...

class AttackExecutor(Protocol):
    """Контракт для исполнителей атак"""
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        ...
    
    @property
    def module_name(self) -> str:
        ...

class EventSerializer:
    """Сериализатор событий в разные форматы"""
    
    @staticmethod
    def to_json(event) -> str:
        import json
        return json.dumps(event.to_dict(), indent=2, ensure_ascii=False)
    
    @staticmethod
    def to_csv(event) -> str:
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Заголовок
        writer.writerow(['event_id', 'type', 'source', 'timestamp'])
        
        # Данные
        event_dict = event.to_dict()
        writer.writerow([
            event_dict['event_id'],
            event_dict['type'],
            event_dict['source'],
            event_dict['timestamp']
        ])
        
        return output.getvalue()