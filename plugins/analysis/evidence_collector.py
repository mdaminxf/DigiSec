import os
import json
from core.models import ToolResult
from core.registry import register_tool
from core.workspace import isolate_evidence, validate_path_security, log_audit_event

@register_tool
def collect_evidence(filepath: str, case_id: str = "default") -> ToolResult:
    """Safely collects evidence by verifying path security and symlinking it into the case isolation workspace.
    
    CRITICAL RULE: DO NOT use raw bash commands (cp, mv, ln) to collect evidence. You MUST use this tool
    to ensure proper chain-of-custody, zero-spoliation, and audit logging.
    
    This tool takes an absolute path to any evidence file (e.g., memory dump, disk image, logs),
    validates that it doesn't escape sandbox boundaries, and safely links it into the 
    cases/<case_id>/raw/ directory.
    
    Returns the new isolated path that you should use for all subsequent analysis (Volatility, etc.).
    
    Args:
        filepath: Absolute path to the evidence file.
        case_id: The case identifier.
    """
    log_audit_event(case_id, "collect_evidence", {"filepath": filepath}, "Attempting collection", "in_progress")
    
    path_check = validate_path_security(filepath)
    if not path_check.get("safe", False):
        err = path_check.get("error", "Unknown path validation error")
        log_audit_event(case_id, "collect_evidence", {"filepath": filepath}, f"Blocked: {err}", "blocked")
        return ToolResult(
            tool_name="collect_evidence",
            success=False,
            errors=[json.dumps({
                "error": err,
                "exit_code": 1,
                "recoverable": False,
                "stderr_payload": err,
                "suggestion": "Ensure evidence path is within valid sandbox bounds"
            })]
        )

    if not os.path.exists(filepath):
        log_audit_event(case_id, "collect_evidence", {"filepath": filepath}, "File not found", "error")
        return ToolResult(
            tool_name="collect_evidence",
            success=False,
            errors=[json.dumps({
                "error": f"File not found: {filepath}",
                "exit_code": 1,
                "recoverable": True,
                "stderr_payload": f"No such file: {filepath}",
                "suggestion": "Verify the image path is correct and the file exists"
            })]
        )

    try:
        isolated_path = isolate_evidence(filepath, case_id)
        log_audit_event(case_id, "collect_evidence", {"filepath": filepath, "isolated_path": isolated_path}, "Collection successful", "success")
        
        return ToolResult(
            tool_name="collect_evidence",
            success=True,
            data=[{
                "original_path": filepath,
                "isolated_path": isolated_path,
                "message": f"Evidence safely isolated to {isolated_path}. Use this path for all further analysis."
            }]
        )
    except Exception as e:
        log_audit_event(case_id, "collect_evidence", {"filepath": filepath}, f"Collection failed: {str(e)}", "error")
        return ToolResult(
            tool_name="collect_evidence",
            success=False,
            errors=[json.dumps({
                "error": f"Failed to isolate evidence: {str(e)}",
                "exit_code": 1,
                "recoverable": True,
                "stderr_payload": str(e),
                "suggestion": "Check file permissions or case directory access"
            })]
        )
