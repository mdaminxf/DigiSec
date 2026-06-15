from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class ValidationResult(BaseModel):
    """Result of validating a single finding against its supporting evidence."""
    finding_id: str
    finding_title: str
    is_valid: bool
    confidence_original: float
    confidence_adjusted: float
    supporting_artifact_count: int
    cross_source: bool = False
    issues: List[str] = []
    recommendation: str = ""


class LoopDetection(BaseModel):
    """Result of checking for execution loops in the orchestrator."""
    detected: bool = False
    repeated_capability: Optional[str] = None
    iteration_count: int = 0
    recommendation: str = ""


class CoverageReport(BaseModel):
    """Assessment of how well the investigation covers its objectives."""
    total_objectives: int
    satisfied_objectives: int
    coverage_pct: float
    unsatisfied: List[str] = []
    suggested_actions: List[str] = []


class WatchmanVerdict(BaseModel):
    """The Watchman's overall verdict after a capability execution."""
    should_continue: bool
    reason: str = ""
    loop_detected: bool = False
    hallucination_flags: List[str] = []
    validated_findings: List[ValidationResult] = []
    coverage: Optional[CoverageReport] = None
    new_queue_items: List[Dict[str, Any]] = []
    iteration: int = 0
    max_iterations: int = 50
