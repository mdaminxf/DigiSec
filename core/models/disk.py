from pydantic import BaseModel
from typing import Optional

class MFTEntry(BaseModel):
    entry_number: int
    filename: str
    filepath: str
    size: int
    created: Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None
    is_deleted: bool = False

class PrefetchEntry(BaseModel):
    executable: str
    run_count: int
    last_run: Optional[str] = None
    previous_runs: list[str] = []

class AmcacheEntry(BaseModel):
    filepath: str
    sha1: Optional[str] = None
    last_modified: Optional[str] = None
    publisher: Optional[str] = None

class ShimcacheEntry(BaseModel):
    filepath: str
    last_modified: Optional[str] = None
    exec_flag: bool = False

class EventLogEntry(BaseModel):
    event_id: int
    source: str
    timestamp: Optional[str] = None
    computer: Optional[str] = None
    message: Optional[str] = None
    level: Optional[str] = None

class RegistryArtifact(BaseModel):
    hive: str
    key_path: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    last_modified: Optional[str] = None
