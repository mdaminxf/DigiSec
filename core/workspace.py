import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

BASE_CASES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cases")


def get_case_name(filepath: str) -> str:
    """Extract a simple case name from a file path."""
    base = os.path.basename(filepath)
    name = os.path.splitext(base)[0].lower()
    if '-' in name:
        return name.split('-')[0]
    if '_' in name:
        return name.split('_')[0]
    return name


def isolate_evidence(filepath: str, case_id: Optional[str] = None) -> str:
    """Symlinks the original evidence into the case's raw/ directory to enforce isolation."""
    if not os.path.isabs(filepath):
        filepath = os.path.abspath(filepath)
        
    if case_id is None:
        case_id = get_case_name(filepath)
        
    dirs = get_workspace(case_id)
    raw_dir = dirs["raw"]
    
    filename = os.path.basename(filepath)
    link_path = os.path.join(raw_dir, filename)
    
    if not os.path.exists(link_path):
        try:
            os.symlink(filepath, link_path)
        except OSError:
            pass
            
    return link_path


def get_workspace(case_id: str) -> dict:
    """Create and return the standardized case workspace directories.
    
    Layout:
        cases/<case_id>/
        ├── raw/
        ├── parsed/
        ├── findings/
        ├── timelines/
        ├── graph/
        ├── watchman/
        ├── reports/
        └── logs/
    """
    case_dir = os.path.join(BASE_CASES_DIR, case_id)
    dirs = {
        "root": case_dir,
        "raw": os.path.join(case_dir, "raw"),
        "parsed": os.path.join(case_dir, "parsed"),
        "findings": os.path.join(case_dir, "findings"),
        "timelines": os.path.join(case_dir, "timelines"),
        "graph": os.path.join(case_dir, "graph"),
        "watchman": os.path.join(case_dir, "watchman"),
        "reports": os.path.join(case_dir, "reports"),
        "logs": os.path.join(case_dir, "logs"),
    }

    for d in dirs.values():
        os.makedirs(d, exist_ok=True)

    return dirs


def save_json(case_id: str, subdir: str, filename: str, data):
    """Save a JSON file to a case workspace subdirectory."""
    dirs = get_workspace(case_id)
    path = os.path.join(dirs.get(subdir, dirs["root"]), filename)
    with open(path, "w") as f:
        if hasattr(data, "model_dump"):
            json.dump(data.model_dump(), f, indent=2, default=str)
        else:
            json.dump(data, f, indent=2, default=str)
    return path


def load_json(case_id: str, subdir: str, filename: str) -> Optional[dict]:
    """Load a JSON file from a case workspace subdirectory."""
    dirs = get_workspace(case_id)
    path = os.path.join(dirs.get(subdir, dirs["root"]), filename)
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None


def get_parsed_artifact(case_id: str, artifact_name: str) -> Optional[dict]:
    """Load a previously parsed artifact from the case workspace."""
    return load_json(case_id, "parsed", f"{artifact_name}.json")


def save_parsed_artifact(case_id: str, artifact_name: str, data):
    """Save a parsed artifact to the case workspace."""
    return save_json(case_id, "parsed", f"{artifact_name}.json", data)


def save_finding(case_id: str, finding_name: str, data):
    """Save a finding to the case workspace."""
    return save_json(case_id, "findings", f"{finding_name}.json", data)


def save_timeline(case_id: str, data):
    """Save the attack timeline to the case workspace."""
    return save_json(case_id, "timelines", "attack_timeline.json", data)


def get_report_path(case_id: str, ext: str = "pdf") -> str:
    """Get the path for the final report file."""
    dirs = get_workspace(case_id)
    return os.path.join(dirs["reports"], f"final_report.{ext}")


def save_state(case_id: str, state):
    """Save the investigation state to the case root."""
    return save_json(case_id, "root", "state.json", state)


def load_state(case_id: str) -> Optional[dict]:
    """Load the investigation state from the case root."""
    return load_json(case_id, "root", "state.json")


def save_plan(case_id: str, plan):
    """Save the investigation plan to the case root."""
    return save_json(case_id, "root", "plan.json", plan)


def load_plan(case_id: str) -> Optional[dict]:
    """Load the investigation plan from the case root."""
    return load_json(case_id, "root", "plan.json")


def log_audit_event(case_id: str, tool_name: str, parameters: dict, result_summary: str, status: str = "success", tokens_used: int = 0, execution_duration_ms: float = 0):
    """Log an event to the provenance audit ledger."""
    dirs = get_workspace(case_id)
    log_file = os.path.join(dirs["logs"], "provenance_audit.jsonl")
    
    param_str = json.dumps(parameters, sort_keys=True, default=str)
    param_hash = hashlib.sha256(param_str.encode()).hexdigest()[:16]
    
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": tool_name,
        "parameters": parameters,
        "parameter_hash": param_hash,
        "result_summary": result_summary,
        "status": status,
        "tokens_used": tokens_used,
        "execution_duration_ms": execution_duration_ms
    }
    
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")


def validate_path_security(filepath: str, allowed_roots: list = None) -> dict:
    """Ensure a file path does not escape allowed sandbox boundaries."""
    if allowed_roots is None:
        allowed_roots = [
            BASE_CASES_DIR, 
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'mount_point'),
            os.path.expanduser("~")
        ]
        
    try:
        resolved = Path(filepath).resolve()
        
        for root in allowed_roots:
            root_resolved = Path(root).resolve()
            if hasattr(resolved, 'is_relative_to'):
                if resolved.is_relative_to(root_resolved):
                    return {"safe": True, "resolved_path": str(resolved), "error": None}
            else:
                if str(resolved).startswith(str(root_resolved)):
                    return {"safe": True, "resolved_path": str(resolved), "error": None}
                    
        return {
            "safe": False, 
            "resolved_path": str(resolved), 
            "error": f"Path traversal violation: {resolved} escapes sandbox boundaries"
        }
    except Exception as e:
        return {"safe": False, "resolved_path": filepath, "error": str(e)}

