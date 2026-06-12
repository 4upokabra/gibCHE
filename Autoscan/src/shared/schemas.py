from pydantic import BaseModel
from typing import Dict, Any

class NormalizedEvent(BaseModel):
    event_id: str
    type: str
    source: str
    timestamp: str
    data: Dict[str, Any]
    metadata: Dict[str, Any]