from core.disk_backend import run_disk_tool
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_amcache

@register_tool
def get_amcache(amcache_file: str, limit: int = 100) -> ToolResult:
    """Parses the Amcache.hve registry hive to uncover evidence of recently executed applications and their SHA1 hashes."""
    data = run_disk_tool("amcacheparser", ["-f", amcache_file, "--json"])
    entries = parse_amcache(data)
    return ToolResult(
        tool_name="get_amcache",
        success=True,
        data=[e.model_dump() for e in entries[:limit]]
    )
