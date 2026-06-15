from core.learning import record_case, get_learning_history, get_common_misses, get_common_false_positives, get_improvement_suggestions
from core.models import ToolResult
from core.registry import register_tool


@register_tool
def record_investigation(case_id: str, findings: list[str], missed: list[str], false_positives: list[str]) -> ToolResult:
    """Records the results of a completed investigation into the Persistent Learning Loop to help the agent learn from missed findings or false positives."""
    record_case(
        case_id=case_id,
        findings=[{"title": f} for f in findings],
        missed=missed,
        false_positives=false_positives
    )

    return ToolResult(
        tool_name="record_investigation",
        success=True,
        data={"case_id": case_id, "recorded": True}
    )


@register_tool
def get_learning_insights() -> ToolResult:
    """Analyzes the Persistent Learning Loop database to provide insights on commonly missed attacker techniques and frequent false positives."""
    history = get_learning_history()
    common_misses = get_common_misses()
    common_fps = get_common_false_positives()
    suggestions = get_improvement_suggestions()

    return ToolResult(
        tool_name="get_learning_insights",
        success=True,
        data={
            "total_cases": len(history),
            "common_misses": common_misses,
            "common_false_positives": common_fps,
            "improvement_suggestions": suggestions
        }
    )
