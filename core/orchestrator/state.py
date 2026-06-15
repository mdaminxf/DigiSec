import json
from typing import Optional
from datetime import datetime
from core.models.case import InvestigationState, InvestigationStatus, InvestigationPlan
from core.workspace import save_json, load_json


class StateEngine:
    """Persistent state manager for investigations.
    
    Every mutation is immediately written to disk so investigations
    can be resumed after crashes or network drops.
    """

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.state: Optional[InvestigationState] = None

    def initialize(self, plan: InvestigationPlan) -> InvestigationState:
        """Create a new investigation state from an approved plan."""
        self.state = InvestigationState(
            case_id=plan.case_id,
            status=InvestigationStatus.RUNNING,
            started_at=datetime.now().isoformat(),
        )
        self._persist()
        return self.state

    def load(self) -> Optional[InvestigationState]:
        """Load existing state from disk for resumption."""
        data = load_json(self.case_id, "root", "state.json")
        if data:
            self.state = InvestigationState(**data)
        return self.state

    def mark_capability_complete(self, capability: str):
        """Record that a capability has been executed."""
        if capability not in self.state.completed_capabilities:
            self.state.completed_capabilities.append(capability)
        self.state.iterations += 1
        self._persist()

    def mark_phase(self, phase_id: str):
        """Update the current phase."""
        self.state.current_phase = phase_id
        self._persist()

    def record_error(self, error: str):
        """Record an execution error."""
        self.state.errors.append(error)
        self._persist()

    def update_findings_count(self, count: int):
        """Update the total findings count."""
        self.state.findings_count = count
        self._persist()

    def update_verdict(self, verdict_dict: dict):
        """Store the latest Watchman verdict."""
        self.state.last_watchman_verdict = verdict_dict
        self._persist()

    def complete(self):
        """Mark the investigation as completed."""
        self.state.status = InvestigationStatus.COMPLETED
        self.state.completed_at = datetime.now().isoformat()
        self._persist()

    def fail(self, reason: str):
        """Mark the investigation as failed."""
        self.state.status = InvestigationStatus.FAILED
        self.state.errors.append(reason)
        self.state.completed_at = datetime.now().isoformat()
        self._persist()

    def pause(self):
        """Pause the investigation."""
        self.state.status = InvestigationStatus.PAUSED
        self._persist()

    def _persist(self):
        """Write state to disk immediately."""
        if self.state:
            save_json(self.case_id, "root", "state.json", self.state)
