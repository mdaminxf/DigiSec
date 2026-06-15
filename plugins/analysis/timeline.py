from core.timeline import TimelineEvent, build_timeline, detect_temporal_anomalies
from core.models import ToolResult
from core.registry import register_tool
from core.os_detect import detect_os
from core.memory_backend import execute_capability
from core.parsers import parse_pslist, parse_netscan
from core.workspace import get_case_name, save_timeline

@register_tool
def build_attack_timeline(memory_file: str) -> ToolResult:
    """Merges memory, disk, and event log artifacts into a single unified chronological attack timeline, highlighting temporal anomalies."""
    case_name = get_case_name(memory_file)
    os_name = detect_os(memory_file)
    if os_name == "unknown":
        raise Exception("Could not determine OS")

    events = []

    # Memory: processes
    raw_procs = execute_capability(memory_file, "processes", os_name)
    processes = parse_pslist(raw_procs, os_name)
    for p in processes:
        if p.create_time and p.create_time != "None" and p.create_time != "":
            events.append(TimelineEvent(
                timestamp=p.create_time,
                source="memory",
                event_type="process_start",
                description=f"{p.name} started (PID {p.pid})",
                artifact=f"{os_name}.pslist",
                pid=p.pid
            ))

    # Memory: network
    raw_net = execute_capability(memory_file, "network", os_name)
    network = parse_netscan(raw_net, os_name)
    for conn in network:
        events.append(TimelineEvent(
            timestamp="",
            source="memory",
            event_type="network_connection",
            description=f"PID {conn.pid} connected to {conn.remote_ip}:{conn.remote_port}",
            artifact=f"{os_name}.netscan",
            pid=conn.pid
        ))

    timeline = build_timeline(events)
    anomalies = detect_temporal_anomalies(events)
    
    # Dump to workspace
    save_timeline(case_name, {"timeline": timeline, "anomalies": anomalies})

    return ToolResult(
        tool_name="build_attack_timeline",
        success=True,
        data={
            "case_workspace": f"cases/{case_name}/",
            "total_events": len(timeline),
            "timeline": timeline,
            "anomalies": anomalies
        }
    )
