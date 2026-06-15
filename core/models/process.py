from pydantic import BaseModel
from typing import Optional

class Process(BaseModel):
    pid: int
    ppid: int
    name: str
    create_time: Optional[str] = None
    exit_time: Optional[str] = None
    cmdline: Optional[str] = None
