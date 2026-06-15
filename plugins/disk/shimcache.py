from core.disk_backend import run_disk_tool
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_shimcache

@register_tool
def get_shimcache(system_hive: str, limit: int = 100) -> ToolResult:
    """Extracts Application Compatibility Cache (Shimcache) entries to determine if an executable was run on the system."""
    data = run_disk_tool("shimcacheparser", ["-i", system_hive, "--json"])
    entries = parse_shimcache(data)
    return ToolResult(
        tool_name="get_shimcache",
        success=True,
        data=[e.model_dump() for e in entries[:limit]]
    )
