from core.disk_backend import run_disk_tool
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_prefetch

@register_tool
def get_prefetch(prefetch_dir: str, limit: int = 100) -> ToolResult:
    """Analyzes Windows Prefetch files to determine the execution history of applications, including execution counts and timestamps."""
    data = run_disk_tool("pecmd", ["-d", prefetch_dir, "--json"])
    entries = parse_prefetch(data)
    return ToolResult(
        tool_name="get_prefetch",
        success=True,
        data=[e.model_dump() for e in entries[:limit]]
    )
