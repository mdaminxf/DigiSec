import json
import subprocess
import os
from core.workspace import get_case_name, get_parsed_artifact, save_parsed_artifact

def run_disk_tool(tool: str, args: list[str], case_id: str = None) -> list[dict]:
    if case_id is None:
        case_id = "disk_analysis"
        for arg in args:
            if arg.endswith(('.img', '.raw', '.vhd', '.dd', '.E01')):
                case_id = get_case_name(arg)
                break
            
    plugin_name = f"{tool}_{'_'.join(args).replace('/', '_')[:20]}"
    
    cached = get_parsed_artifact(case_id, plugin_name)
    if cached is not None:
        return cached

    cmd = [tool] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return [{
            "error": f"{tool} command not found",
            "exit_code": 1,
            "recoverable": True,
            "stderr_payload": f"{tool} not installed or not in PATH",
            "suggestion": f"Ensure {tool} is installed and in PATH"
        }]

    if result.returncode != 0:
        return [{
            "error": f"{tool} failed: {result.stderr}",
            "exit_code": result.returncode,
            "recoverable": True,
            "stderr_payload": result.stderr,
            "suggestion": f"Check parameters for {tool}"
        }]

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        data = [{"raw": line} for line in result.stdout.strip().split("\n") if line.strip()]

    save_parsed_artifact(case_id, plugin_name, data)
    return data
