from typing import List, Dict, Any
from core.models import PrefetchEntry

def parse_prefetch(data: List[Dict[str, Any]]) -> List[PrefetchEntry]:
    entries = []
    for item in data:
        entries.append(PrefetchEntry(
            executable=item.get("Executable", ""),
            run_count=item.get("RunCount", 0),
            last_run=str(item.get("LastRun", "")),
            previous_runs=[str(r) for r in item.get("PreviousRuns", [])]
        ))
    return entries
