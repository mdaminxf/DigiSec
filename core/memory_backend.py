from core.os_detect import detect_os
from core.plugin_map import PLUGIN_MAP
from core.volatility import run_plugin

from core.workspace import isolate_evidence

def execute_capability(memory_file: str, capability: str, os_name: str = None):
    memory_file = isolate_evidence(memory_file)
    if not os_name:
        os_name = detect_os(memory_file)

    if os_name == "unknown":
        raise Exception("Could not determine OS")

    plugin = PLUGIN_MAP[os_name][capability]

    return run_plugin(memory_file, plugin)
