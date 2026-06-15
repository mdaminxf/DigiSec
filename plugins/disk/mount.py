"""MCP tool for mounting forensic disk images in read-only mode.

Provides structured, auditable disk image mounting that enforces
read-only access to preserve evidence integrity. Supports E01
(Expert Witness) format through ewfmount and raw images through
loopback mounting.

Forensic Guardrails:
- All mounts use read-only flags (ro,noexec,nodev,nosuid)
- Path traversal protection via resolve() validation
- Full audit trail logging to provenance_audit.jsonl
- Structured error returns for autonomous self-correction
"""

import subprocess
import os
import uuid
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from core.models import ToolResult
from core.registry import register_tool
from core.workspace import isolate_evidence, get_workspace, validate_path_security

# Trusted root directories for path validation
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
ALLOWED_ROOTS = [
    str(PROJECT_ROOT / "cases"),
    str(PROJECT_ROOT / "mount_point"),
]

def _validate_path(filepath: str) -> dict:
    try:
        resolved = Path(filepath).resolve()
        for root in ALLOWED_ROOTS:
            root_resolved = Path(root).resolve()
            if hasattr(resolved, 'is_relative_to') and resolved.is_relative_to(root_resolved):
                return {"safe": True, "resolved_path": str(resolved)}
            elif str(resolved).startswith(str(root_resolved)):
                return {"safe": True, "resolved_path": str(resolved)}
        # Also allow direct evidence file paths (user may specify absolute path to image)
        if resolved.exists() and resolved.is_file():
            return {"safe": True, "resolved_path": str(resolved)}
        return {
            "safe": False,
            "resolved_path": str(resolved),
            "error": f"Path traversal violation: {resolved} escapes sandbox boundaries"
        }
    except Exception as e:
        return {"safe": False, "error": str(e)}

def _log_audit(case_id: str, tool_name: str, parameters: dict, result_summary: str, status: str = "success"):
    try:
        dirs = get_workspace(case_id)
        audit_file = os.path.join(dirs["logs"], "provenance_audit.jsonl")
        
        param_str = json.dumps(parameters, sort_keys=True, default=str)
        param_hash = hashlib.sha256(param_str.encode()).hexdigest()[:16]
        
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_name": tool_name,
            "parameters": parameters,
            "parameter_hash": param_hash,
            "result_summary": result_summary,
            "status": status,
            "tokens_used": 0,
            "execution_duration_ms": 0
        }
        
        with open(audit_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

@register_tool
def mount_e01_image(e01_path: str, case_id: str = "default") -> ToolResult:
    """CRITICAL RULE: DO NOT USE RAW BASH TO MOUNT. YOU MUST USE THIS TOOL TO PREVENT EVIDENCE SPOLIATION.
    
    Mounts an E01 forensic image and its NTFS file system so artifacts can be accessed.
    
    This is required before running other disk plugins (MFT, Prefetch, Registry).
    It automatically uses ewfmount and ntfs-3g to expose the raw file system.
    All mounts enforce read-only (ro,noexec,nodev,nosuid,loop) flags to prevent
    any modification to the original evidence.
    
    Returns the path to the mounted volume where files like $MFT, Windows/Prefetch, etc. 
    are located. Use this returned path for subsequent disk analysis tools.
    
    Args:
        e01_path: Absolute path to the E01 or raw disk image file.
        case_id: Case identifier for audit logging (default: 'default').
    """
    _log_audit(case_id, "mount_e01_image", {"e01_path": e01_path}, "Attempting mount", "in_progress")
    
    path_check = validate_path_security(e01_path)
    if not path_check.get("safe", False):
        err = path_check.get("error", "Unknown path validation error")
        _log_audit(case_id, "mount_e01_image", {"e01_path": e01_path}, f"Blocked: {err}", "blocked")
        return ToolResult(
            tool_name="mount_e01_image", 
            success=False, 
            errors=[json.dumps({
                "error": err,
                "exit_code": 1,
                "recoverable": False,
                "stderr_payload": err,
                "suggestion": "Use a valid path within the sandbox boundaries"
            })]
        )
    
    if not os.path.exists(e01_path):
        _log_audit(case_id, "mount_e01_image", {"e01_path": e01_path}, "File not found", "error")
        return ToolResult(
            tool_name="mount_e01_image", 
            success=False, 
            errors=[json.dumps({
                "error": f"File not found: {e01_path}",
                "exit_code": 1,
                "recoverable": True,
                "stderr_payload": f"No such file: {e01_path}",
                "suggestion": "Verify the image path is correct and the file exists"
            })]
        )
        
    e01_path = isolate_evidence(e01_path, case_id)
        
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    mount_point_dir = os.path.join(base_dir, "mount_point")
    
    mount_id = str(uuid.uuid4())[:8]
    ewf_dir = os.path.join(mount_point_dir, "e01_containers", mount_id)
    vol_dir = os.path.join(mount_point_dir, "ntfs_volumes", mount_id)
    
    os.makedirs(ewf_dir, exist_ok=True)
    os.makedirs(vol_dir, exist_ok=True)
    
    ewf1_path = os.path.join(ewf_dir, "ewf1")
    is_ewf = False
    
    try:
        res_ewf = subprocess.run(["sudo", "ewfmount", e01_path, ewf_dir], capture_output=True, text=True)
        if res_ewf.returncode == 0 or "already mounted" in res_ewf.stderr:
            if os.path.exists(ewf1_path):
                is_ewf = True
    except FileNotFoundError:
        pass # ewfmount not installed, fallback to raw
        
    # If ewfmount succeeded, mount the ewf1 container. Otherwise, assume it's a raw DD image and mount directly.
    target_image = ewf1_path if is_ewf else e01_path
        
    mount_cmd = [
        "sudo", "ntfs-3g", "-o", "ro,noexec,nodev,nosuid,loop,recover,show_sys_files,streams_interface=windows", 
        target_image, vol_dir
    ]
    try:
        res_mount = subprocess.run(mount_cmd, capture_output=True, text=True)
        if res_mount.returncode != 0 and "already mounted" not in res_mount.stderr:
            _log_audit(case_id, "mount_e01_image", {"e01_path": e01_path}, "ntfs-3g mount failed", "error")
            return ToolResult(
                tool_name="mount_e01_image", 
                success=False, 
                errors=[json.dumps({
                    "error": f"NTFS mount failed: {res_mount.stderr}",
                    "exit_code": res_mount.returncode,
                    "recoverable": True,
                    "stderr_payload": res_mount.stderr,
                    "suggestion": "Check if volume is valid NTFS or requires offset"
                })]
            )
    except FileNotFoundError:
        _log_audit(case_id, "mount_e01_image", {"e01_path": e01_path}, "ntfs-3g not installed", "error")
        return ToolResult(
            tool_name="mount_e01_image", 
            success=False, 
            errors=[json.dumps({
                "error": "ntfs-3g command not found",
                "exit_code": 1,
                "recoverable": True,
                "stderr_payload": "ntfs-3g not in PATH",
                "suggestion": "Install ntfs-3g (apt install ntfs-3g)"
            })]
        )
        
    _log_audit(case_id, "mount_e01_image", {"e01_path": e01_path}, "Mount successful", "success")
    return ToolResult(
        tool_name="mount_e01_image",
        success=True,
        data=[{
            "mounted_volume_path": vol_dir,
            "mft_path": os.path.join(vol_dir, "$MFT"),
            "prefetch_dir": os.path.join(vol_dir, "Windows/Prefetch"),
            "system_hive": os.path.join(vol_dir, "Windows/System32/config/SYSTEM"),
            "software_hive": os.path.join(vol_dir, "Windows/System32/config/SOFTWARE"),
            "amcache_hive": os.path.join(vol_dir, "Windows/AppCompat/Programs/Amcache.hve"),
            "evtx_dir": os.path.join(vol_dir, "Windows/System32/winevt/Logs"),
            "users_dir": os.path.join(vol_dir, "Users")
        }]
    )
