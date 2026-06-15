from typing import List, Dict, Any
from core.models import Process

def parse_pslist(data: List[Dict[str, Any]], os_name: str) -> List[Process]:
    processes = []
    for item in data:
        if os_name == "windows":
            processes.append(Process(
                pid=item.get("PID", 0) or 0,
                ppid=item.get("PPID", 0) or 0,
                name=item.get("ImageFileName", "") or "",
                create_time=str(item.get("CreateTime", "")),
                exit_time=str(item.get("ExitTime", ""))
            ))
        elif os_name == "linux":
            processes.append(Process(
                pid=item.get("PID", 0) or 0,
                ppid=item.get("PPID", 0) or 0,
                name=item.get("Comm", "") or ""
            ))
        elif os_name == "mac":
            processes.append(Process(
                pid=item.get("PID", 0) or 0,
                ppid=item.get("PPID", 0) or 0,
                name=item.get("Name", "") or ""
            ))
    return processes
