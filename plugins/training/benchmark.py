from core.benchmark import benchmark_case, load_benchmark_history
from core.models import ToolResult
from core.registry import register_tool


@register_tool
def run_benchmark(case_name: str, finding_titles: list[str], ground_truth: list[str]) -> ToolResult:
    """Executes a forensic baseline benchmark against a known ground-truth dataset to calculate True Positive / False Positive rates and evaluate agent accuracy."""
    from core.models import Finding, Evidence

    findings = [
        Finding(
            title=title,
            description="benchmark entry",
            severity="medium",
            confidence=0.5,
            evidence=[Evidence(source="benchmark", artifact=title, confidence=0.5)]
        )
        for title in finding_titles
    ]

    result = benchmark_case(case_name, findings, ground_truth)

    return ToolResult(
        tool_name="run_benchmark",
        success=True,
        data=result.to_dict()
    )


@register_tool
def get_benchmark_history() -> ToolResult:
    """Retrieves the historical accuracy scores (Precision/Recall/F1) to track the agent's performance improvements over time."""
    history = load_benchmark_history()
    return ToolResult(
        tool_name="get_benchmark_history",
        success=True,
        data=history
    )
