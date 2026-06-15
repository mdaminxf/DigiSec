from core.memory_backend import execute_capability
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_pslist, parse_psscan
from core.os_detect import detect_os

@register_tool
def find_hidden_processes(memory_file: str) -> ToolResult:
    """Cross-references the active process linked list (pslist) against memory pool allocations (psscan) to detect rootkit-hidden or unlinked processes."""
    os_name = detect_os(memory_file)
    
    if os_name == "windows":
        raw_pslist = execute_capability(memory_file, "processes", os_name)
        pslist = parse_pslist(raw_pslist, os_name)
        
        raw_psscan = execute_capability(memory_file, "hidden_processes", os_name)
        psscan = parse_psscan(raw_psscan, os_name)
        
        pslist_pids = {p.pid for p in pslist}
        hidden = [p.model_dump() for p in psscan if p.pid not in pslist_pids]
    else:
        hidden = []
        
    return ToolResult(
        tool_name="find_hidden_processes",
        success=True,
        data=hidden
    )
