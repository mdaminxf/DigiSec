from core.graph import EvidenceGraph
from core.models import ToolResult
from core.registry import register_tool
from core.os_detect import detect_os
from core.memory_backend import execute_capability
from core.parsers import parse_pslist, parse_netscan, parse_malfind, parse_cmdline


@register_tool
def build_evidence_graph(memory_file: str) -> ToolResult:
    """Constructs an interconnected Evidence Graph mapping the relationships between processes, files, registry keys, and network connections to reveal attack chains."""
    os_name = detect_os(memory_file)
    if os_name == "unknown":
        raise Exception("Could not determine OS")

    graph = EvidenceGraph()

    raw_procs = execute_capability(memory_file, "processes", os_name)
    processes = parse_pslist(raw_procs, os_name)

    cmdlines = {}
    if os_name != "mac":
        raw_cmd = execute_capability(memory_file, "cmdline", os_name)
        cmdlines = parse_cmdline(raw_cmd, os_name)

    raw_net = execute_capability(memory_file, "network", os_name)
    network = parse_netscan(raw_net, os_name)

    raw_inj = execute_capability(memory_file, "malfind", os_name)
    injections = parse_malfind(raw_inj, os_name)

    # Add process nodes
    for p in processes:
        graph.add_node(
            node_id=f"proc_{p.pid}",
            node_type="process",
            label=p.name,
            properties={"pid": p.pid, "ppid": p.ppid, "cmdline": cmdlines.get(p.pid, "")}
        )

    # Add parent-child edges
    pid_set = {p.pid for p in processes}
    for p in processes:
        if p.ppid in pid_set:
            graph.add_edge(f"proc_{p.ppid}", f"proc_{p.pid}", "spawned", p.create_time)

    # Add network nodes and edges
    for conn in network:
        net_id = f"net_{conn.remote_ip}_{conn.remote_port}"
        graph.add_node(
            node_id=net_id,
            node_type="network",
            label=f"{conn.remote_ip}:{conn.remote_port}",
            properties={"protocol": conn.protocol, "state": conn.state}
        )
        graph.add_edge(f"proc_{conn.pid}", net_id, "connected_to")

    # Add injection nodes and edges
    for inj in injections:
        inj_id = f"injection_{inj.pid}_{inj.address}"
        graph.add_node(
            node_id=inj_id,
            node_type="injection",
            label=f"Injected @ {inj.address}",
            properties={"protection": inj.protection}
        )
        graph.add_edge(f"proc_{inj.pid}", inj_id, "injected_memory")

    return ToolResult(
        tool_name="build_evidence_graph",
        success=True,
        data=graph.to_dict()
    )
