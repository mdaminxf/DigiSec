from typing import List, Dict, Any
from core.models import AmcacheEntry

def parse_amcache(data: List[Dict[str, Any]]) -> List[AmcacheEntry]:
    entries = []
    for item in data:
        entries.append(AmcacheEntry(
            filepath=item.get("FilePath", ""),
            sha1=item.get("SHA1", None),
            last_modified=str(item.get("LastModified", "")),
            publisher=item.get("Publisher", None)
        ))
    return entries
