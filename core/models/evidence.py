from pydantic import BaseModel
from typing import Optional

class Evidence(BaseModel):
    source: str
    artifact: str
    confidence: float
    timestamp: Optional[str] = None
