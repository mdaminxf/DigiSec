from core.memory_backend import execute_capability
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_pslist
from core.os_detect import detect_os

@register_tool
def get_processes(memory_file: str, limit: int = 100) -> ToolResult:
    """Extracts and parses the active process list from a memory image. Use this to identify running executables and their basic attributes."""
    os_name = detect_os(memory_file)
    data = execute_capability(memory_file, "processes", os_name)
    processes = parse_pslist(data, os_name)

    return ToolResult(
        tool_name="get_processes",
        success=True,
        data=[p.model_dump() for p in processes[:limit]]
    )
