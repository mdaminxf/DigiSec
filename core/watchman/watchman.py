import hashlib
import json
from typing import List, Dict, Any, Optional
from core.models.case import InvestigationState, QueueItem, Objective, PhaseStatus
from core.models.watchman import (
    ValidationResult, LoopDetection, CoverageReport, WatchmanVerdict
)
from core.models.finding import Finding
from core.workspace import save_json


class Watchman:
    """The Watchman validation subsystem.
    
    Sits between the Orchestrator and the State Engine.
    Validates every capability execution for:
    - Empty/invalid results
    - Findings without supporting evidence (hallucinations)
    - Execution loops (same capability running repeatedly)
    - Objective coverage tracking
    - Iteration limits
    """

    def __init__(self, case_id: str, max_iterations: int = 50):
        self.case_id = case_id
        self.max_iterations = max_iterations
        self.execution_history: Dict[str, int] = {}  # capability_hash -> count
        self.audit_log: List[Dict[str, Any]] = []

    def _hash_execution(self, capability: str, args: Dict[str, Any]) -> str:
        """Create a unique hash for a capability+args combination."""
        key = f"{capability}_{json.dumps(args, sort_keys=True)}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    def validate_result(self, capability: str, result: Any) -> bool:
        """Check if a capability result is non-empty and structurally valid."""
        if result is None:
            return False
        if isinstance(result, list) and len(result) == 0:
            return False
        if isinstance(result, dict) and not result:
            return False
        if isinstance(result, str) and not result.strip():
            return False
        return True

    def validate_finding(self, finding: Finding) -> ValidationResult:
        """Validate a single finding against its supporting evidence.
        
        A finding is flagged as a potential hallucination if:
        - It has 0 supporting artifacts
        - Its confidence is below 0.3
        """
        issues = []
        artifact_count = len(finding.evidence)
        cross_source = len(set(e.source.split(".")[0] for e in finding.evidence)) > 1

        if artifact_count == 0:
            issues.append("HALLUCINATION: Finding has zero supporting artifacts")

        if finding.confidence < 0.3:
            issues.append(f"LOW_CONFIDENCE: {finding.confidence:.2f} is below threshold")

        # Adjust confidence based on evidence strength
        artifact_multiplier = min(artifact_count / 2.0, 1.0)
        cross_bonus = 1.15 if cross_source else 1.0
        adjusted = min(finding.confidence * artifact_multiplier * cross_bonus, 1.0)

        is_valid = artifact_count > 0 and finding.confidence >= 0.3

        recommendation = ""
        if not is_valid:
            recommendation = "REJECT: Insufficient evidence to support this finding."
        elif adjusted < 0.5:
            recommendation = "DEMOTE: Mark as unconfirmed and seek additional evidence."

        return ValidationResult(
            finding_id=finding.title,
            finding_title=finding.title,
            is_valid=is_valid,
            confidence_original=finding.confidence,
            confidence_adjusted=round(adjusted, 3),
            supporting_artifact_count=artifact_count,
            cross_source=cross_source,
            issues=issues,
            recommendation=recommendation,
        )

    def check_loops(self, capability: str, args: Dict[str, Any], max_retries: int = 2) -> LoopDetection:
        """Detect if a capability is being executed in a loop."""
        exec_hash = self._hash_execution(capability, args)
        count = self.execution_history.get(exec_hash, 0)

        if count >= max_retries:
            return LoopDetection(
                detected=True,
                repeated_capability=capability,
                iteration_count=count,
                recommendation=f"HALT: {capability} has been executed {count} times with identical arguments. Skipping."
            )

        return LoopDetection(detected=False, iteration_count=count)

    def record_execution(self, capability: str, args: Dict[str, Any]):
        """Record that a capability was executed."""
        exec_hash = self._hash_execution(capability, args)
        self.execution_history[exec_hash] = self.execution_history.get(exec_hash, 0) + 1

    def check_coverage(self, objectives: List[Objective]) -> CoverageReport:
        """Assess how well the investigation covers its objectives."""
        total = len(objectives)
        satisfied = sum(1 for o in objectives if o.satisfied)
        unsatisfied = [o.description for o in objectives if not o.satisfied]

        coverage_pct = (satisfied / total * 100) if total > 0 else 0

        suggested = []
        if coverage_pct < 50:
            suggested.append("Less than half of objectives are satisfied. Consider re-prioritizing.")
        if total > 0 and satisfied == total:
            suggested.append("All objectives satisfied. Investigation can proceed to reporting.")

        return CoverageReport(
            total_objectives=total,
            satisfied_objectives=satisfied,
            coverage_pct=round(coverage_pct, 1),
            unsatisfied=unsatisfied,
            suggested_actions=suggested,
        )

    def _suggest_gap_actions(self, findings: List[Finding], completed: List[str]) -> List[Dict[str, Any]]:
        """Suggest new queue items based on evidence gaps."""
        suggestions = []

        has_cred = any("credential" in f.title.lower() or "lsass" in f.description.lower() for f in findings)
        if has_cred and "get_registry_artifacts" not in completed:
            suggestions.append({
                "capability": "get_registry_artifacts",
                "reason": "Credential access detected — registry analysis needed",
                "priority": 2,
            })

        has_persistence = any("persistence" in f.title.lower() for f in findings)
        if has_persistence and "get_event_logs" not in completed:
            suggestions.append({
                "capability": "get_event_logs",
                "reason": "Persistence detected — event log review needed",
                "priority": 2,
            })

        has_lateral = any("lateral" in f.title.lower() for f in findings)
        if has_lateral and "get_event_logs" not in completed:
            suggestions.append({
                "capability": "get_event_logs",
                "reason": "Lateral movement detected — logon event review needed",
                "priority": 2,
            })

        return suggestions

    def evaluate(
        self,
        state: InvestigationState,
        objectives: List[Objective],
        last_capability: str,
        last_args: Dict[str, Any],
        last_result: Any,
        findings: List[Finding],
    ) -> WatchmanVerdict:
        """Run all Watchman checks and produce a verdict.
        
        This is the main entry point called by the Orchestrator after
        every capability execution.
        """
        hallucination_flags = []
        validated = []

        # 1. Validate the result
        result_valid = self.validate_result(last_capability, last_result)
        if not result_valid:
            self._log("EMPTY_RESULT", last_capability, "Result was empty or None")

        # 2. Validate all current findings
        for f in findings:
            vr = self.validate_finding(f)
            validated.append(vr)
            if not vr.is_valid:
                hallucination_flags.append(f"REJECTED: {vr.finding_title} — {', '.join(vr.issues)}")

        # 3. Check for loops
        loop = self.check_loops(last_capability, last_args)
        self.record_execution(last_capability, last_args)

        # 4. Check iteration limit
        over_limit = state.iterations >= self.max_iterations

        # 5. Check coverage
        coverage = self.check_coverage(objectives)

        # 6. Check for evidence gaps and suggest new actions
        new_items = self._suggest_gap_actions(findings, state.completed_capabilities)

        # 7. Determine if we should continue
        should_continue = True
        reason = "Proceeding normally."

        if over_limit:
            should_continue = False
            reason = f"ITERATION LIMIT: Reached {self.max_iterations} iterations. Forcing report generation."
        elif loop.detected:
            # Don't halt the whole investigation, just skip this item
            reason = f"LOOP: {last_capability} skipped due to repeated execution."
        elif coverage.coverage_pct >= 100:
            should_continue = False
            reason = "ALL OBJECTIVES SATISFIED. Proceeding to report generation."

        verdict = WatchmanVerdict(
            should_continue=should_continue,
            reason=reason,
            loop_detected=loop.detected,
            hallucination_flags=hallucination_flags,
            validated_findings=validated,
            coverage=coverage,
            new_queue_items=new_items,
            iteration=state.iterations,
            max_iterations=self.max_iterations,
        )

        # Persist audit trail
        self._log("VERDICT", last_capability, verdict.model_dump())
        save_json(self.case_id, "watchman", f"verdict_{state.iterations:03d}.json", verdict.model_dump())

        return verdict

    def _log(self, event_type: str, capability: str, detail: Any):
        """Add an entry to the internal audit log."""
        self.audit_log.append({
            "event": event_type,
            "capability": capability,
            "detail": detail,
        })
