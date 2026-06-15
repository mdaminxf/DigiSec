from core.os_detect import detect_os
from core.memory_backend import execute_capability
from core.models import ToolResult, Finding, Evidence
from core.registry import register_tool
from core.parsers import parse_pslist, parse_netscan, parse_malfind, parse_cmdline, parse_psscan
from core.correlation import correlate_artifacts
from core.scoring import score_process

@register_tool
def memory_triage(memory_file: str) -> ToolResult:
    """Performs a rapid triage of a memory image, correlating processes, network connections, and code injections to return a prioritized list of high-risk suspicious processes."""
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
            
    hidden_pids = []
    if os_name == "windows":
        raw_psscan = execute_capability(memory_file, "hidden_processes", os_name)
        psscan = parse_psscan(raw_psscan, os_name)
        pslist_pids = {p.pid for p in processes}
        hidden_procs = [p for p in psscan if p.pid not in pslist_pids]
        for hp in hidden_procs:
            hp.cmdline = cmdlines.get(hp.pid)
        processes.extend(hidden_procs)
        hidden_pids = [hp.pid for hp in hidden_procs]
    
    raw_net = execute_capability(memory_file, "network", os_name)
    network = parse_netscan(raw_net, os_name)
    
    raw_inj = execute_capability(memory_file, "malfind", os_name)
    injections = parse_malfind(raw_inj, os_name)

    # Correlation & Scoring
    correlation_map = correlate_artifacts(processes, network, injections, hidden_pids)
    
    high_risk = []
    findings = []
    for pid, evidence in correlation_map.items():
        score_data = score_process(evidence)
        if score_data["severity"] in ["high", "medium"]:
            high_risk.append(score_data)
            
            # Create a structured Finding with Evidence Provenance
            ev_list = []
            if evidence.hidden:
                ev_list.append(Evidence(source=f"{os_name}.psscan", artifact=f"PID {pid}", confidence=1.0))
            if evidence.injections:
                ev_list.append(Evidence(source=f"{os_name}.malfind", artifact=f"PID {pid}", confidence=0.95))
            if evidence.network_connections:
                ev_list.append(Evidence(source=f"{os_name}.netscan", artifact=f"PID {pid}", confidence=0.9))
            if score_data["reasons"] and "powershell -enc" in str(score_data["reasons"]):
                ev_list.append(Evidence(source=f"{os_name}.cmdline", artifact=f"PID {pid}", confidence=0.95))
                
            findings.append(Finding(
                title=f"Suspicious Process: {evidence.process.name} (PID {pid})",
                description=" | ".join(score_data["reasons"]),
                severity=score_data["severity"],
                confidence=0.85,
                evidence=ev_list
            ))

    summary = {
        "os": os_name,
        "process_count": len(processes),
        "high_risk_processes": len(high_risk),
        "scored_details": high_risk
    }

    return ToolResult(
        tool_name="memory_triage",
        success=True,
        data=summary,
        findings=findings
    )
