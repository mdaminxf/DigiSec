import subprocess
import json
from core.models import ToolResult
from core.registry import register_tool

@register_tool
def verify_dependencies() -> ToolResult:
    """Checks for required forensic binaries and suggests remediation if missing.
    
    Verifies the existence of critical tools like volatility3, ewfmount, ntfs-3g,
    and sleuthkit tools in the system path.
    """
    deps = {
        "vol": "pip install volatility3",
        "ewfmount": "apt-get install ewf-tools",
        "ntfs-3g": "apt-get install ntfs-3g",
        "mmls": "apt-get install sleuthkit"
    }
    
    results = {}
    missing = []
    
    for cmd, fix in deps.items():
        try:
            res = subprocess.run(["which", cmd], capture_output=True, text=True)
            if res.returncode == 0:
                results[cmd] = {"status": "installed", "path": res.stdout.strip()}
            else:
                results[cmd] = {"status": "missing", "suggestion": fix}
                missing.append(cmd)
        except Exception as e:
            results[cmd] = {"status": "error", "error": str(e)}
            missing.append(cmd)
            
    success = len(missing) == 0
    return ToolResult(
        tool_name="verify_dependencies",
        success=success,
        data=[{"dependencies": results, "missing": missing}]
    )
