from typing import List, Dict, Any
from core.models import ShimcacheEntry

def parse_shimcache(data: List[Dict[str, Any]]) -> List[ShimcacheEntry]:
    entries = []
    for item in data:
        entries.append(ShimcacheEntry(
            filepath=item.get("FilePath", ""),
            last_modified=str(item.get("LastModified", "")),
            exec_flag=item.get("ExecFlag", False)
        ))
    return entries
