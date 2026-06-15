from typing import List, Dict, Any
from core.models import InjectedRegion

def parse_malfind(data: List[Dict[str, Any]], os_name: str) -> List[InjectedRegion]:
    injections = []
    for item in data:
        if os_name == "windows":
            injections.append(InjectedRegion(
                pid=item.get("PID", 0) or 0,
                process_name=item.get("Process", "") or "",
                address=str(item.get("Start VPN", "")),
                protection=str(item.get("Protection", ""))
            ))
        elif os_name in ["linux", "mac"]:
            injections.append(InjectedRegion(
                pid=item.get("PID", 0) or 0,
                process_name=item.get("Process", "") or "",
                address=str(item.get("Start", "")),
                protection=str(item.get("Protection", ""))
            ))
    return injections
