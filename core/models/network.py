from pydantic import BaseModel
from typing import Optional

class NetworkConnection(BaseModel):
    pid: int
    process_name: Optional[str] = None
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    state: Optional[str] = None
