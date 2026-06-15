from core.memory_backend import execute_capability
from core.models import ToolResult, Finding, Evidence
from core.registry import register_tool
from core.parsers import parse_malfind
from core.os_detect import detect_os

@register_tool
def detect_code_injection(memory_file: str, limit: int = 100) -> ToolResult:
    """Scans memory for injected code, hollowed processes, and RWX memory regions (malfind). Crucial for detecting fileless malware and in-memory payloads."""
    os_name = detect_os(memory_file)
    data = execute_capability(memory_file, "malfind", os_name)
    injections = parse_malfind(data, os_name)
    
    findings = []
    for inj in injections[:limit]:
        findings.append(Finding(
            title="Injected Memory Region",
            description=f"Found RWX or injected memory in PID {inj.pid} ({inj.process_name})",
            severity="high",
            confidence=0.95,
            evidence=[Evidence(
                source=f"{os_name}.malfind",
                artifact=f"Address {inj.address}",
                confidence=0.95
            )]
        ))

    return ToolResult(
        tool_name="detect_code_injection",
        success=True,
        data=[i.model_dump() for i in injections[:limit]],
        findings=findings
    )
