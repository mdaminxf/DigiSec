from pydantic import BaseModel
from typing import Optional

class InjectedRegion(BaseModel):
    pid: int
    process_name: Optional[str] = None
    address: str
    protection: str
