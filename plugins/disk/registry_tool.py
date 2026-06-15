from core.disk_backend import run_disk_tool
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_registry

@register_tool
def get_registry_artifacts(hive_file: str, limit: int = 100) -> ToolResult:
    """Extracts critical forensic artifacts from Windows Registry hives (e.g., persistence mechanisms in Run keys)."""
    data = run_disk_tool("regripper", ["-r", hive_file, "--json"])
    entries = parse_registry(data)
    return ToolResult(
        tool_name="get_registry_artifacts",
        success=True,
        data=[e.model_dump() for e in entries[:limit]]
    )
