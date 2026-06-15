from typing import List, Dict, Any

def parse_cmdline(data: List[Dict[str, Any]], os_name: str) -> Dict[int, str]:
    cmdlines = {}
    for item in data:
        pid = item.get("PID", 0)
        args = item.get("Args", "")
        if pid and args:
            cmdlines[pid] = str(args)
    return cmdlines
