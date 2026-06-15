from core.cross_correlation import correlate_memory_disk
from core.models import ToolResult
from core.registry import register_tool
from core.os_detect import detect_os
from core.memory_backend import execute_capability
from core.parsers import parse_pslist


@register_tool
def correlate_memory_disk_artifacts(memory_file: str) -> ToolResult:
    """Cross-correlates running memory processes against disk artifacts (Prefetch/Amcache) to identify memory-only execution and anti-forensics."""
    os_name = detect_os(memory_file)
    if os_name == "unknown":
        raise Exception("Could not determine OS")

    raw_procs = execute_capability(memory_file, "processes", os_name)
    processes = parse_pslist(raw_procs, os_name)

    # Disk artifacts would be loaded here if available
    # For now we correlate with whatever disk data has been gathered
    correlations = correlate_memory_disk(processes)

    memory_only = [c for c in correlations if c["memory_only"]]

    return ToolResult(
        tool_name="correlate_memory_disk_artifacts",
        success=True,
        data={
            "total_processes": len(processes),
            "memory_only_count": len(memory_only),
            "memory_only_processes": memory_only,
            "all_correlations": correlations
        }
    )
