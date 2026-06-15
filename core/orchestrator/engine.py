import traceback
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from core.models.case import (
    InvestigationPlan, InvestigationState, InvestigationStatus,
    QueueItem, PhaseStatus, Objective
)
from core.models.finding import Finding, ToolResult
from core.orchestrator.state import StateEngine
from core.watchman.watchman import Watchman
from core.workspace import save_json, save_finding, save_parsed_artifact
from core.registry import get_tools


class Orchestrator:
    """The autonomous investigation orchestrator.
    
    Executes the investigation plan by:
    1. Popping items from the execution queue in priority order
    2. Checking dependencies before execution
    3. Executing capabilities (internal tools)
    4. Running Watchman validation after every step
    5. Dynamically adjusting the queue based on findings
    6. Tracking objective satisfaction
    7. Persisting all state to disk
    """

    def __init__(self, plan: InvestigationPlan):
        self.plan = plan
        self.case_id = plan.case_id
        self.state_engine = StateEngine(self.case_id)
        self.watchman = Watchman(self.case_id, max_iterations=50)
        self.findings: List[Finding] = []
        self.tool_map: Dict[str, Callable] = self._build_tool_map()
        self.execution_log: List[Dict[str, Any]] = []

    def _build_tool_map(self) -> Dict[str, Callable]:
        """Build a mapping from capability names to actual tool functions."""
        tools = get_tools()
        return {tool.__name__: tool for tool in tools}

    def _check_dependencies(self, item: QueueItem) -> bool:
        """Check if all phase dependencies are satisfied."""
        phase = next((p for p in self.plan.phases if p.id == item.phase_id), None)
        if not phase or not phase.depends_on:
            return True

        completed_phases = set()
        for p in self.plan.phases:
            if p.status == PhaseStatus.COMPLETED:
                completed_phases.add(p.id)

        return all(dep in completed_phases for dep in phase.depends_on)

    def _execute_capability(self, item: QueueItem) -> Any:
        """Execute a single capability and return its result."""
        func = self.tool_map.get(item.capability)
        if not func:
            raise RuntimeError(f"Unknown capability: {item.capability}")

        item.started_at = datetime.now().isoformat()
        result = func(**item.args)
        item.completed_at = datetime.now().isoformat()

        return result

    def _extract_findings(self, result: Any) -> List[Finding]:
        """Extract Finding objects from a tool result."""
        if isinstance(result, ToolResult):
            return result.findings
        return []

    def _update_phase_status(self, phase_id: str):
        """Mark a phase as completed if all its capabilities are done."""
        phase = next((p for p in self.plan.phases if p.id == phase_id), None)
        if not phase:
            return

        completed_caps = set(self.state_engine.state.completed_capabilities)
        if all(cap in completed_caps for cap in phase.capabilities):
            phase.status = PhaseStatus.COMPLETED
            phase.results_summary = f"Completed {len(phase.capabilities)} capabilities"

    def _inject_queue_items(self, suggestions: List[Dict[str, Any]]):
        """Inject new queue items from Watchman gap analysis."""
        existing_caps = {item.capability for item in self.plan.queue}
        for sug in suggestions:
            cap = sug["capability"]
            if cap not in existing_caps and cap not in self.state_engine.state.completed_capabilities:
                self.plan.queue.append(QueueItem(
                    capability=cap,
                    args={},  # Will need evidence paths
                    phase_id="dynamic_gap_fill",
                    priority=sug.get("priority", 3),
                    result_key=cap,
                ))

    def run(self) -> Dict[str, Any]:
        """Execute the full investigation autonomously.
        
        This is the main execution loop. It runs until:
        - The queue is empty
        - All objectives are satisfied
        - The iteration limit is reached
        - Watchman halts execution
        """
        state = self.state_engine.initialize(self.plan)

        # Sort queue by priority
        pending_queue = [q for q in self.plan.queue if q.status == PhaseStatus.PENDING]
        pending_queue.sort(key=lambda q: q.priority)

        while pending_queue and state.status == InvestigationStatus.RUNNING:
            item = pending_queue.pop(0)

            # Check dependencies
            if not self._check_dependencies(item):
                pending_queue.append(item)  # Re-queue for later
                continue

            # Update phase status
            self.state_engine.mark_phase(item.phase_id)

            # Execute
            log_entry = {
                "iteration": state.iterations,
                "capability": item.capability,
                "phase": item.phase_id,
                "status": "started",
                "timestamp": datetime.now().isoformat(),
            }

            try:
                result = self._execute_capability(item)
                item.status = PhaseStatus.COMPLETED
                log_entry["status"] = "completed"

                # Store parsed result
                if isinstance(result, ToolResult) and result.data:
                    save_parsed_artifact(self.case_id, item.capability, result.data)

                # Extract findings
                new_findings = self._extract_findings(result)
                self.findings.extend(new_findings)

                # Save findings
                if new_findings:
                    save_finding(self.case_id, item.capability, [
                        f.model_dump() for f in new_findings
                    ])

            except Exception as e:
                item.status = PhaseStatus.FAILED
                item.error_message = str(e)
                log_entry["status"] = "failed"
                log_entry["error"] = str(e)
                self.state_engine.record_error(f"{item.capability}: {str(e)}")

                # Retry logic
                if item.retry_count < item.max_retries:
                    item.retry_count += 1
                    item.status = PhaseStatus.PENDING
                    pending_queue.append(item)

            # Record completion
            self.state_engine.mark_capability_complete(item.capability)
            self._update_phase_status(item.phase_id)
            self.state_engine.update_findings_count(len(self.findings))

            # Run Watchman
            verdict = self.watchman.evaluate(
                state=state,
                objectives=self.plan.objectives,
                last_capability=item.capability,
                last_args=item.args,
                last_result=None,  # Don't pass raw result to save memory
                findings=self.findings,
            )
            self.state_engine.update_verdict(verdict.model_dump())

            # Inject gap-filling actions
            if verdict.new_queue_items:
                self._inject_queue_items(verdict.new_queue_items)
                # Re-sort
                pending_queue.sort(key=lambda q: q.priority)

            # Check if we should stop
            if not verdict.should_continue:
                log_entry["watchman_halt"] = verdict.reason
                break

            self.execution_log.append(log_entry)

        # Finalize
        self.state_engine.complete()

        # Save execution log
        save_json(self.case_id, "logs", "execution_log.json", self.execution_log)

        # Save final plan state
        save_json(self.case_id, "root", "plan.json", self.plan)

        return self._build_summary()

    def _build_summary(self) -> Dict[str, Any]:
        """Build the final investigation summary."""
        coverage = self.watchman.check_coverage(self.plan.objectives)

        return {
            "case_id": self.case_id,
            "case_type": self.plan.case_type.value,
            "status": self.state_engine.state.status.value,
            "total_iterations": self.state_engine.state.iterations,
            "findings_count": len(self.findings),
            "findings": [f.model_dump() for f in self.findings],
            "phases_completed": sum(1 for p in self.plan.phases if p.status == PhaseStatus.COMPLETED),
            "phases_total": len(self.plan.phases),
            "coverage": coverage.model_dump(),
            "errors": self.state_engine.state.errors,
            "workspace": f"cases/{self.case_id}/",
        }
