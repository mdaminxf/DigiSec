from core.disk_backend import run_disk_tool
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_mft

@register_tool
def get_mft_timeline(disk_image: str, limit: int = 100) -> ToolResult:
    """Parses the NTFS Master File Table ($MFT) to reconstruct file creation, modification, and deletion timelines."""
    data = run_disk_tool("analyze_mft", ["-f", disk_image, "--output-format", "json"])
    entries = parse_mft(data)
    return ToolResult(
        tool_name="get_mft_timeline",
        success=True,
        data=[e.model_dump() for e in entries[:limit]]
    )
