from pydantic import BaseModel
from typing import List, Any, Optional
from core.models.evidence import Evidence

class Finding(BaseModel):
    title: str
    description: str
    severity: str
    confidence: float
    evidence: List[Evidence]
    requires_validation: bool = True
    alternative_explanations: List[str] = []
    inferences: List[str] = []

class ToolResult(BaseModel):
    tool_name: str
    success: bool
    data: Optional[Any] = None
    findings: List[Finding] = []
    errors: List[str] = []
