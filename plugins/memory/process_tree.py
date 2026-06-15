from core.memory_backend import execute_capability
from core.models import ToolResult
from core.registry import register_tool
from core.parsers import parse_pslist
from core.os_detect import detect_os
from collections import defaultdict

@register_tool
def get_process_tree(memory_file: str) -> ToolResult:
    """Generates a hierarchical parent-child process tree from memory. Use this to visualize process lineage and spot anomalous child processes (e.g., cmd.exe spawned by word.exe)."""
    os_name = detect_os(memory_file)
    data = execute_capability(memory_file, "processes", os_name)
    processes = parse_pslist(data, os_name)
    
    tree = defaultdict(list)
    process_map = {}
    for p in processes:
        process_map[p.pid] = p.model_dump()
        tree[p.ppid].append(p.pid)
        
    def build_node(pid):
        node = process_map.get(pid, {"pid": pid, "name": "Unknown"}).copy()
        children = [build_node(child_pid) for child_pid in tree.get(pid, [])]
        if children:
            node["children"] = children
        return node
        
    roots = [p.pid for p in processes if p.ppid not in process_map]
    forest = [build_node(pid) for pid in roots]
    
    return ToolResult(
        tool_name="get_process_tree",
        success=True,
        data=forest
    )
