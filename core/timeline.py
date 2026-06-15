from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class TimelineEvent(BaseModel):
    timestamp: str
    source: str  # memory, mft, evtx, prefetch, registry, usn
    event_type: str  # process_start, file_create, login, network, etc
    description: str
    artifact: Optional[str] = None
    pid: Optional[int] = None
    confidence: float = 1.0


def build_timeline(events: List[TimelineEvent]) -> List[Dict[str, Any]]:
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    return [e.model_dump() for e in sorted_events]


def detect_temporal_anomalies(events: List[TimelineEvent]) -> List[Dict[str, Any]]:
    anomalies = []
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    for i in range(len(sorted_events) - 1):
        current = sorted_events[i]
        next_event = sorted_events[i + 1]

        # Detect rapid succession events (potential automated attack)
        if current.timestamp and next_event.timestamp:
            if current.timestamp[:16] == next_event.timestamp[:16]:  # same minute
                if current.source != next_event.source:
                    anomalies.append({
                        "type": "rapid_succession",
                        "events": [current.model_dump(), next_event.model_dump()],
                        "description": f"Multiple artifact sources active in same minute: {current.source} and {next_event.source}"
                    })

    return anomalies
