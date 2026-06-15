import os
import yaml
from pathlib import Path
from core.registry import register_tool
from core.models import ToolResult

def load_yaml_plugins():
    """Finds all .yaml and .yml files in the plugins directory and creates dynamic tools."""
    plugins_dir = Path(__file__).parent.parent / "plugins"
    
    for root, dirs, files in os.walk(plugins_dir):
        for file in files:
            if file.endswith(".yaml") or file.endswith(".yml"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r") as f:
                        spec = yaml.safe_load(f)
                    
                    # Some files might have multiple tools as a list, or a single tool dict
                    if isinstance(spec, list):
                        for tool_spec in spec:
                            create_and_register_yaml_tool(tool_spec)
                    elif isinstance(spec, dict):
                        create_and_register_yaml_tool(spec)
                except Exception as e:
                    print(f"Warning: Failed to load YAML plugin {filepath}: {e}")

def create_and_register_yaml_tool(spec):
    name = spec.get("name")
    description = spec.get("description", "")
    args_spec = spec.get("arguments", {})
    command_template = spec.get("command")
    
    if not name or not command_template:
        print(f"Warning: YAML tool missing 'name' or 'command'. Skipping.")
        return
        
    # Build function signature
    args_str = []
    for arg_name, arg_details in args_spec.items():
        arg_type = arg_details.get("type", "str")
        args_str.append(f"{arg_name}: {arg_type}")
    
    sig = ", ".join(args_str)
    
    # Build a python function dynamically using exec so FastMCP sees the correct signature
    # We use python's f-string formatting to inject the arguments into the command
    func_code = f"""
def {name}({sig}) -> ToolResult:
    \"\"\"{description}\"\"\"
    import subprocess
    from core.models import ToolResult
    
    # Map the dynamic arguments
    local_args = locals()
    
    # Format the command template using the arguments
    cmd_template = \"\"\"{command_template}\"\"\"
    cmd_str = cmd_template.format(**local_args)
    
    try:
        res = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            return ToolResult(tool_name="{name}", success=False, errors=[res.stderr.strip() or res.stdout.strip()])
            
        return ToolResult(tool_name="{name}", success=True, data=res.stdout.strip())
    except Exception as e:
        return ToolResult(tool_name="{name}", success=False, errors=[str(e)])
"""
    
    local_env = {}
    # We need to make ToolResult available to the exec environment
    exec(func_code, globals(), local_env)
    
    func = local_env[name]
    register_tool(func)
