import os
import importlib
from pathlib import Path
from fastmcp import FastMCP
from core.registry import get_tools
from core.yaml_loader import load_yaml_plugins

def load_plugins():
    """Dynamically discover and import all plugins in the plugins directory.
    
    This makes the MCP server infinitely extendable. Anyone can drop a new 
    directory (e.g. plugins/cloud, plugins/mobile) or a new .py file into 
    the plugins directory, use @register_tool, and it will be automatically 
    exposed to the AI.
    """
    plugins_dir = Path(__file__).parent / "plugins"
    
    for root, dirs, files in os.walk(plugins_dir):
        if "__pycache__" in root:
            continue
            
        for file in files:
            if file.endswith(".py") and not file.startswith("__"):
                # Convert filepath to python module path (e.g. plugins.memory.processes)
                rel_path = os.path.relpath(os.path.join(root, file), start=Path(__file__).parent)
                module_name = rel_path.replace(os.sep, ".")[:-3]
                try:
                    importlib.import_module(module_name)
                except Exception as e:
                    print(f"Warning: Failed to load dynamically discovered plugin {module_name}: {e}")

# Automatically load all tools across all domains
load_plugins()
load_yaml_plugins()

mcp = FastMCP(
    name="Extensible-DFIR-MCP",
    instructions="""CRITICAL RULES FOR AI AGENT:
1. ZERO SPOLIATION: You are strictly FORBIDDEN from using raw Bash commands to mount disk images or extract memory.
2. USE MCP TOOLS: You MUST use the provided type-safe MCP tools for all actions (e.g., `mount_e01_image`, `get_processes`). 
3. If an MCP tool fails, do not fall back to raw bash. Read the error and self-correct your MCP tool parameters."""
)

# Register all dynamically discovered tools to the FastMCP server
for tool in get_tools():
    mcp.tool()(tool)

if __name__ == "__main__":
    mcp.run()
