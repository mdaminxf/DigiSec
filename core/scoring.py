from core.correlation import ProcessEvidence
from typing import Dict, Any

def score_process(evidence: ProcessEvidence) -> Dict[str, Any]:
    score = 0
    reasons = []
    
    cmdline = (evidence.process.cmdline or "").lower()
    
    if "powershell" in evidence.process.name.lower() and ("-enc" in cmdline or "-e " in cmdline):
        score += 30
        reasons.append("powershell -enc detected")
        
    if evidence.network_connections:
        score += 20
        reasons.append(f"{len(evidence.network_connections)} external network connections")
        
    if evidence.injections:
        score += 50
        reasons.append(f"{len(evidence.injections)} injected memory regions")
        
    if evidence.process.ppid == 0:
        score += 25
        reasons.append("Unknown parent process")
        
    if evidence.hidden:
        score += 80
        reasons.append("Process hidden (unlinked from active process list)")

    severity = "low"
    if score >= 75:
        severity = "high"
    elif score >= 30:
        severity = "medium"

    return {
        "pid": evidence.process.pid,
        "name": evidence.process.name,
        "score": score,
        "severity": severity,
        "reasons": reasons
    }
