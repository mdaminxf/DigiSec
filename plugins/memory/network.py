from core.memory_backend import execute_capability
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_netscan
from core.os_detect import detect_os

@register_tool
def get_network_connections(memory_file: str, limit: int = 100) -> ToolResult:
    """Extracts active and terminated network connections from memory. Use this to identify external C2 beaconing, lateral movement, or reverse shells."""
    os_name = detect_os(memory_file)
    data = execute_capability(memory_file, "network", os_name)
    conns = parse_netscan(data, os_name)

    return ToolResult(
        tool_name="get_network_connections",
        success=True,
        data=[c.model_dump() for c in conns[:limit]]
    )
