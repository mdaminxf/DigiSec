from typing import List, Dict, Any
from core.models import EventLogEntry

def parse_evtx(data: List[Dict[str, Any]]) -> List[EventLogEntry]:
    entries = []
    for item in data:
        entries.append(EventLogEntry(
            event_id=item.get("EventID", 0),
            source=item.get("Source", ""),
            timestamp=str(item.get("TimeCreated", "")),
            computer=item.get("Computer", None),
            message=item.get("Message", None),
            level=item.get("Level", None)
        ))
    return entries
