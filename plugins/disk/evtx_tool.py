from core.disk_backend import run_disk_tool
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_evtx

@register_tool
def get_event_logs(evtx_file: str, limit: int = 100) -> ToolResult:
    """Parses Windows Event Logs (EVTX) to identify logins, service creation, scheduled tasks, and lateral movement."""
    data = run_disk_tool("chainsaw", ["search", evtx_file, "--json"])
    entries = parse_evtx(data)
    return ToolResult(
        tool_name="get_event_logs",
        success=True,
        data=[e.model_dump() for e in entries[:limit]]
    )
