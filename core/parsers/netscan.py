from typing import List, Dict, Any
from core.models import NetworkConnection

def parse_netscan(data: List[Dict[str, Any]], os_name: str) -> List[NetworkConnection]:
    conns = []
    for item in data:
        if os_name == "windows":
            conns.append(NetworkConnection(
                pid=item.get("PID", 0) or 0,
                process_name=item.get("Owner", "") or "",
                local_ip=str(item.get("LocalAddr", "")),
                local_port=item.get("LocalPort", 0) or 0,
                remote_ip=str(item.get("ForeignAddr", "")),
                remote_port=item.get("ForeignPort", 0) or 0,
                protocol=str(item.get("Protocol", "")),
                state=str(item.get("State", ""))
            ))
        elif os_name == "linux":
            conns.append(NetworkConnection(
                pid=item.get("PID", 0) or 0,
                local_ip=str(item.get("LocalAddress", "")),
                local_port=item.get("LocalPort", 0) or 0,
                remote_ip=str(item.get("RemoteAddress", "")),
                remote_port=item.get("RemotePort", 0) or 0,
                protocol=str(item.get("Protocol", "")),
                state=str(item.get("State", ""))
            ))
    return conns
