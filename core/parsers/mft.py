from typing import List, Dict, Any
from core.models import MFTEntry

def parse_mft(data: List[Dict[str, Any]]) -> List[MFTEntry]:
    entries = []
    for item in data:
        entries.append(MFTEntry(
            entry_number=item.get("EntryNumber", 0),
            filename=item.get("FileName", ""),
            filepath=item.get("FilePath", ""),
            size=item.get("FileSize", 0),
            created=str(item.get("Created", "")),
            modified=str(item.get("Modified", "")),
            accessed=str(item.get("Accessed", "")),
            is_deleted=item.get("IsDeleted", False)
        ))
    return entries
