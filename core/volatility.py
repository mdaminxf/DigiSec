import json
import subprocess
from core.workspace import get_case_name, get_parsed_artifact, save_parsed_artifact

VOL = "vol"

def run_plugin(memory_file: str, plugin: str, case_id: str = None):
    if case_id is None:
        case_id = get_case_name(memory_file)
    
    # 1. Check if we already have the parsed JSON artifact in the case workspace
    cached_data = get_parsed_artifact(case_id, plugin)
    if cached_data is not None:
        return cached_data

    # 2. If not, run Volatility
    cmd = [
        VOL,
        "-f",
        memory_file,
        "-r",
        "json",
        plugin,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return {
            "error": "Volatility 3 is not installed or not in PATH",
            "exit_code": 1,
            "recoverable": True,
            "stderr_payload": "vol command not found",
            "suggestion": "Install Volatility 3: pip install volatility3"
        }

    if result.returncode != 0:
        return {
            "error": result.stderr.strip() or "Unknown error",
            "exit_code": result.returncode,
            "recoverable": True,
            "stderr_payload": result.stderr,
            "suggestion": "Check memory image path and plugin name"
        }

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "error": "Failed to parse Volatility output as JSON",
            "exit_code": result.returncode,
            "recoverable": True,
            "stderr_payload": result.stderr,
            "suggestion": "Try running the plugin without -r json flag"
        }
    
    # 3. Save the newly parsed JSON to the case workspace
    save_parsed_artifact(case_id, plugin, data)
    
    return data
