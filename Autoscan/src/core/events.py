from datetime import datetime
from typing import Dict, Any

class BaseEvent:
    def __init__(self, event_id: str, event_type: str, source: str, data: Dict[str, Any]):
        self.event_id = event_id
        self.type = event_type
        self.source = source
        self.timestamp = datetime.now()
        self.data = data

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "type": self.type,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data
        }