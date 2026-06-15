from typing import List, Dict, Any
from core.models import Finding, Evidence


class InvestigationPlan:
    def __init__(self):
        self.completed_steps: List[str] = []
        self.pending_steps: List[str] = []
        self.gaps: List[Dict[str, Any]] = []
        self.findings: List[Finding] = []

    def add_completed(self, step: str):
        self.completed_steps.append(step)

    def add_gap(self, gap_type: str, description: str, suggested_action: str):
        self.gaps.append({
            "type": gap_type,
            "description": description,
            "suggested_action": suggested_action
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "completed_steps": self.completed_steps,
            "pending_steps": self.pending_steps,
            "evidence_gaps": self.gaps,
            "findings_count": len(self.findings)
        }


def check_evidence_gaps(findings: List[Finding], completed_capabilities: List[str]) -> List[Dict[str, Any]]:
    gaps = []

    has_cred_finding = any("credential" in f.title.lower() or "lsass" in f.description.lower() for f in findings)
    if has_cred_finding and "lsass_dump" not in completed_capabilities:
        gaps.append({
            "type": "missing_analysis",
            "description": "Credential access detected but no LSASS analysis performed",
            "suggested_action": "Run LSASS memory analysis for credential extraction indicators",
            "priority": "high"
        })

    has_persistence = any("persistence" in f.title.lower() for f in findings)
    if has_persistence and "registry" not in completed_capabilities:
        gaps.append({
            "type": "missing_analysis",
            "description": "Persistence detected but registry not analyzed",
            "suggested_action": "Analyze registry run keys and scheduled tasks",
            "priority": "high"
        })

    has_lateral = any("lateral" in f.title.lower() for f in findings)
    if has_lateral and "event_logs" not in completed_capabilities:
        gaps.append({
            "type": "missing_analysis",
            "description": "Lateral movement detected but event logs not reviewed",
            "suggested_action": "Review Security and System event logs for logon events",
            "priority": "high"
        })

    has_injection = any("inject" in f.title.lower() for f in findings)
    if has_injection and "dll_analysis" not in completed_capabilities:
        gaps.append({
            "type": "missing_analysis",
            "description": "Code injection detected but DLLs not analyzed",
            "suggested_action": "Run DLL list analysis on injected processes",
            "priority": "medium"
        })

    if "disk_correlation" not in completed_capabilities:
        gaps.append({
            "type": "missing_correlation",
            "description": "Memory findings not correlated with disk artifacts",
            "suggested_action": "Run memory-disk correlation to verify findings",
            "priority": "medium"
        })

    return gaps
