from core.training import explain_finding
from core.models import ToolResult, Finding, Evidence
from core.registry import register_tool
from core.os_detect import detect_os
from core.memory_backend import execute_capability
from core.parsers import parse_pslist, parse_netscan, parse_malfind, parse_cmdline
from core.correlation import correlate_artifacts
from core.detection_engine import run_all_detections


@register_tool
def explain_findings(memory_file: str) -> ToolResult:
    """Maps identified forensic findings to MITRE ATT&CK categories and provides educational explanations and investigation next steps for analysts."""
    os_name = detect_os(memory_file)
    if os_name == "unknown":
        raise Exception("Could not determine OS")

    raw_procs = execute_capability(memory_file, "processes", os_name)
    processes = parse_pslist(raw_procs, os_name)

    cmdlines = {}
    if os_name != "mac":
        raw_cmd = execute_capability(memory_file, "cmdline", os_name)
        cmdlines = parse_cmdline(raw_cmd, os_name)
        for p in processes:
            p.cmdline = cmdlines.get(p.pid)

    raw_net = execute_capability(memory_file, "network", os_name)
    network = parse_netscan(raw_net, os_name)

    raw_inj = execute_capability(memory_file, "malfind", os_name)
    injections = parse_malfind(raw_inj, os_name)

    correlation_map = correlate_artifacts(processes, network, injections, [])
    findings = run_all_detections(correlation_map)

    explanations = [explain_finding(f) for f in findings]

    return ToolResult(
        tool_name="explain_findings",
        success=True,
        data={
            "total_findings": len(findings),
            "explanations": explanations
        }
    )
