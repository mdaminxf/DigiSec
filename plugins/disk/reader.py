import os
import json
from core.models import ToolResult
from core.registry import register_tool
from core.workspace import validate_path_security, log_audit_event

@register_tool
def read_evidence_chunk(filepath: str, start_line: int, end_line: int, case_id: str = "default") -> ToolResult:
    """Reads a bounded chunk of lines from a forensic evidence file to prevent context window exhaustion.
    
    Use this tool when you need to read logs or large text outputs. Do not read more than 
    50-100 lines at a time.
    
    Args:
        filepath: Absolute path to the file to read.
        start_line: The first line to read (1-indexed).
        end_line: The last line to read (inclusive).
        case_id: Case identifier for audit logging.
    """
    log_audit_event(case_id, "read_evidence_chunk", 
                    {"filepath": filepath, "start_line": start_line, "end_line": end_line}, 
                    "Attempting read", "in_progress")

    path_check = validate_path_security(filepath)
    if not path_check.get("safe", False):
        err = path_check.get("error", "Unknown path validation error")
        log_audit_event(case_id, "read_evidence_chunk", {"filepath": filepath}, f"Blocked: {err}", "blocked")
        return ToolResult(
            tool_name="read_evidence_chunk",
            success=False,
            errors=[json.dumps({
                "error": err,
                "exit_code": 1,
                "recoverable": False,
                "stderr_payload": err,
                "suggestion": "Ensure path is within valid sandbox bounds"
            })]
        )

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = []
            for i, line in enumerate(f, 1):
                if i >= start_line and i <= end_line:
                    lines.append(line)
                elif i > end_line:
                    break
        
        log_audit_event(case_id, "read_evidence_chunk", {"filepath": filepath}, "Read successful", "success")
        return ToolResult(
            tool_name="read_evidence_chunk",
            success=True,
            data=[{"lines": lines}]
        )
    except Exception as e:
        log_audit_event(case_id, "read_evidence_chunk", {"filepath": filepath}, f"Read failed: {str(e)}", "error")
        return ToolResult(
            tool_name="read_evidence_chunk",
            success=False,
            errors=[json.dumps({
                "error": f"Failed to read file: {str(e)}",
                "exit_code": 1,
                "recoverable": True,
                "stderr_payload": str(e),
                "suggestion": "Check if file exists and is readable text"
            })]
        )
