from core.agent import InvestigationPlan, check_evidence_gaps
from core.models import ToolResult
from core.registry import register_tool
from core.os_detect import detect_os
from core.memory_backend import execute_capability
from core.parsers import parse_pslist, parse_netscan, parse_malfind, parse_cmdline
from core.correlation import correlate_artifacts
from core.detection_engine import run_all_detections
from core.workspace import get_case_name, save_finding

@register_tool
def investigate(memory_file: str) -> ToolResult:
    """The autonomous Self-Correcting DFIR Agent. Automatically orchestrates all memory/disk plugins, correlates data, runs detections, and highlights missing evidence gaps."""
    case_name = get_case_name(memory_file)
    plan = InvestigationPlan()
    os_name = detect_os(memory_file)
    if os_name == "unknown":
        raise Exception("Could not determine OS")
    plan.add_completed("os_detection")

    raw_procs = execute_capability(memory_file, "processes", os_name)
    processes = parse_pslist(raw_procs, os_name)
    plan.add_completed("process_list")

    cmdlines = {}
    if os_name != "mac":
        raw_cmd = execute_capability(memory_file, "cmdline", os_name)
        cmdlines = parse_cmdline(raw_cmd, os_name)
        for p in processes:
            p.cmdline = cmdlines.get(p.pid)
        plan.add_completed("cmdline")

    raw_net = execute_capability(memory_file, "network", os_name)
    network = parse_netscan(raw_net, os_name)
    plan.add_completed("network")

    raw_inj = execute_capability(memory_file, "malfind", os_name)
    injections = parse_malfind(raw_inj, os_name)
    plan.add_completed("malfind")

    correlation_map = correlate_artifacts(processes, network, injections, [])
    plan.add_completed("correlation")
    
    # Save correlated evidence to the workspace
    save_finding(case_name, "correlation_results", {
        pid: {"pid": ev.process.pid, "name": ev.process.name, "network": len(ev.network_connections), "injections": len(ev.injections)}
        for pid, ev in correlation_map.items() if ev.network_connections or ev.injections
    })

    findings = run_all_detections(correlation_map)
    plan.findings = findings
    plan.add_completed("detection_engine")
    
    # Save actual findings to workspace
    save_finding(case_name, "suspicious_processes", [f.model_dump() for f in findings])

    gaps = check_evidence_gaps(findings, plan.completed_steps)
    for gap in gaps:
        plan.add_gap(gap["type"], gap["description"], gap["suggested_action"])

    return ToolResult(
        tool_name="investigate",
        success=True,
        data={
            "case_workspace": f"cases/{case_name}/",
            "plan": plan.to_dict(),
            "findings": [f.model_dump() for f in findings],
            "evidence_gaps": gaps,
            "recommendation": "Review evidence gaps and run suggested actions to strengthen findings."
        }
    )
