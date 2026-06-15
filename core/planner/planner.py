from typing import List, Dict, Any
from core.models.case import (
    CaseType, EvidenceType, EvidenceItem, Objective,
    Phase, QueueItem, InvestigationPlan, PhaseStatus
)


OBJECTIVE_TEMPLATES: Dict[CaseType, List[str]] = {
    CaseType.IP_THEFT: [
        "Identify what data the subject had access to",
        "Determine what data may have been stolen or exfiltrated",
        "Establish how the data was taken (USB, cloud, email, etc.)",
        "Identify where the data was sent or stored",
        "Build a timeline of when the activity occurred",
    ],
    CaseType.MALWARE: [
        "Identify the malware and its capabilities",
        "Determine the initial infection vector",
        "Assess what the malware did on the system (actions on objective)",
        "Determine if persistence mechanisms were established",
        "Identify command-and-control infrastructure",
    ],
    CaseType.RANSOMWARE: [
        "Determine when encryption was triggered",
        "Identify the initial entry vector",
        "Assess whether data was exfiltrated before encryption",
        "Determine the scope of the compromise",
        "Identify the ransomware variant and IOCs",
    ],
    CaseType.INSIDER_THREAT: [
        "Identify what the insider accessed",
        "Determine if data was copied or exfiltrated",
        "Identify the tools and methods used",
        "Build a complete timeline of insider activity",
        "Assess the scope and impact of the breach",
    ],
    CaseType.INCIDENT_RESPONSE: [
        "Determine what happened",
        "Establish when the incident occurred",
        "Assess the scope of the compromise",
        "Determine if the environment is still compromised",
        "Identify remediation steps",
    ],
    CaseType.UNKNOWN: [
        "Perform initial triage of available evidence",
        "Identify any suspicious activity",
        "Build a timeline of events",
    ],
}


PHASE_TEMPLATES = [
    {
        "id": "memory_processes",
        "name": "Memory: Process Analysis",
        "description": "Extract and analyze running processes, process trees, and hidden processes from memory.",
        "requires": [EvidenceType.MEMORY_IMAGE],
        "capabilities": ["get_processes", "get_process_tree", "find_hidden_processes"],
        "priority": 1,
    },
    {
        "id": "memory_network",
        "name": "Memory: Network Analysis",
        "description": "Extract active and historical network connections from memory to identify C2, lateral movement, or data exfiltration.",
        "requires": [EvidenceType.MEMORY_IMAGE],
        "capabilities": ["get_network_connections"],
        "priority": 2,
        "depends_on": ["memory_processes"],
    },
    {
        "id": "memory_injection",
        "name": "Memory: Code Injection Scan",
        "description": "Scan all process memory regions for injected code, hollowed processes, and RWX allocations.",
        "requires": [EvidenceType.MEMORY_IMAGE],
        "capabilities": ["detect_code_injection"],
        "priority": 3,
        "depends_on": ["memory_processes"],
    },
    {
        "id": "disk_execution",
        "name": "Disk: Execution History",
        "description": "Analyze Prefetch, Amcache, and Shimcache to reconstruct what programs were executed.",
        "requires": [EvidenceType.DISK_IMAGE],
        "capabilities": ["get_prefetch", "get_amcache", "get_shimcache"],
        "priority": 2,
    },
    {
        "id": "disk_filesystem",
        "name": "Disk: Filesystem Timeline",
        "description": "Parse the MFT to reconstruct file creation, modification, and deletion activity.",
        "requires": [EvidenceType.DISK_IMAGE],
        "capabilities": ["get_mft_timeline"],
        "priority": 3,
    },
    {
        "id": "disk_events",
        "name": "Disk: Event Log Analysis",
        "description": "Parse Windows Event Logs for logon events, service creation, scheduled tasks, and security alerts.",
        "requires": [EvidenceType.DISK_IMAGE],
        "capabilities": ["get_event_logs"],
        "priority": 3,
    },
    {
        "id": "disk_registry",
        "name": "Disk: Registry Analysis",
        "description": "Extract persistence mechanisms, user activity, and system configuration from registry hives.",
        "requires": [EvidenceType.DISK_IMAGE, EvidenceType.REGISTRY_HIVE],
        "capabilities": ["get_registry_artifacts"],
        "priority": 4,
    },
    {
        "id": "cross_correlation",
        "name": "Cross-Source Correlation",
        "description": "Correlate memory artifacts against disk artifacts to validate findings and detect anti-forensics.",
        "requires": [EvidenceType.MEMORY_IMAGE, EvidenceType.DISK_IMAGE],
        "capabilities": ["correlate_memory_disk_artifacts"],
        "priority": 5,
        "depends_on": ["memory_processes", "disk_execution"],
    },
    {
        "id": "detection_engine",
        "name": "Automated Detection Engine",
        "description": "Run heuristic detections for lateral movement, persistence, credential access, ransomware, and LOLBin abuse.",
        "requires": [],
        "capabilities": ["run_detection_engine"],
        "priority": 6,
        "depends_on": ["memory_processes"],
    },
    {
        "id": "evidence_graph",
        "name": "Evidence Graph Construction",
        "description": "Build an interconnected evidence graph showing relationships between processes, files, network connections, and registry keys.",
        "requires": [],
        "capabilities": ["build_evidence_graph"],
        "priority": 7,
        "depends_on": ["detection_engine"],
    },
    {
        "id": "timeline",
        "name": "Attack Timeline Construction",
        "description": "Merge all artifact timestamps into a unified chronological attack timeline.",
        "requires": [],
        "capabilities": ["build_attack_timeline"],
        "priority": 8,
        "depends_on": ["memory_processes"],
    },
    {
        "id": "reporting",
        "name": "Report Generation",
        "description": "Generate the final Executive PDF and Technical JSON reports with all findings, timeline, and evidence graph.",
        "requires": [],
        "capabilities": ["generate_memory_report"],
        "priority": 9,
        "depends_on": ["detection_engine", "timeline"],
    },
]


def _has_evidence_type(evidence: List[EvidenceItem], required: EvidenceType) -> bool:
    """Check if a specific evidence type is available."""
    return any(e.evidence_type == required for e in evidence)


def _phase_is_applicable(template: dict, evidence: List[EvidenceItem]) -> bool:
    """Determine if a phase template is applicable given the available evidence."""
    requires = template.get("requires", [])
    if not requires:
        return True
    # Phase is applicable if ANY of its required evidence types are present
    return any(_has_evidence_type(evidence, req) for req in requires)


def _get_evidence_path(evidence: List[EvidenceItem], evidence_type: EvidenceType) -> str:
    """Get the file path for a specific evidence type."""
    for e in evidence:
        if e.evidence_type == evidence_type:
            return e.path
    return ""


def _build_capability_args(capability: str, evidence: List[EvidenceItem]) -> Dict[str, Any]:
    """Build the arguments dict for a capability based on available evidence."""
    memory_path = _get_evidence_path(evidence, EvidenceType.MEMORY_IMAGE)
    disk_path = _get_evidence_path(evidence, EvidenceType.DISK_IMAGE)

    memory_capabilities = [
        "get_processes", "get_process_tree", "find_hidden_processes",
        "get_network_connections", "detect_code_injection", "memory_triage",
        "generate_memory_report", "build_evidence_graph",
        "build_attack_timeline", "run_detection_engine",
        "correlate_memory_disk_artifacts",
    ]
    disk_capabilities = [
        "get_mft_timeline", "get_prefetch", "get_amcache",
        "get_shimcache", "get_event_logs", "get_registry_artifacts",
    ]

    if capability in memory_capabilities and memory_path:
        return {"memory_file": memory_path}
    elif capability in disk_capabilities and disk_path:
        return {"disk_image": disk_path}

    args = {}
    if memory_path:
        args["memory_file"] = memory_path
    if disk_path:
        args["disk_image"] = disk_path
    return args


def generate_plan(case_type: CaseType, description: str, evidence: List[EvidenceItem]) -> InvestigationPlan:
    """Generate a complete investigation plan based on case type and available evidence.
    
    This is the core planning engine. It:
    1. Creates investigation objectives based on the case type
    2. Selects applicable phases based on available evidence
    3. Builds an ordered execution queue with correct dependencies
    """
    # 1. Generate objectives
    obj_templates = OBJECTIVE_TEMPLATES.get(case_type, OBJECTIVE_TEMPLATES[CaseType.UNKNOWN])
    objectives = [Objective(description=desc) for desc in obj_templates]

    # 2. Select applicable phases
    phases = []
    for template in PHASE_TEMPLATES:
        if _phase_is_applicable(template, evidence):
            deps = template.get("depends_on", [])
            # Only include dependencies that are themselves applicable
            valid_deps = [d for d in deps if any(
                t["id"] == d and _phase_is_applicable(t, evidence)
                for t in PHASE_TEMPLATES
            )]
            phases.append(Phase(
                id=template["id"],
                name=template["name"],
                description=template["description"],
                capabilities=template["capabilities"],
                depends_on=valid_deps,
            ))

    # 3. Build execution queue
    queue = []
    for phase in phases:
        priority_map = {t["id"]: t.get("priority", 5) for t in PHASE_TEMPLATES}
        for cap in phase.capabilities:
            args = _build_capability_args(cap, evidence)
            queue.append(QueueItem(
                capability=cap,
                args=args,
                phase_id=phase.id,
                priority=priority_map.get(phase.id, 5),
                result_key=cap,
            ))

    # Sort queue by priority
    queue.sort(key=lambda q: q.priority)

    return InvestigationPlan(
        case_type=case_type,
        description=description,
        evidence=evidence,
        objectives=objectives,
        phases=phases,
        queue=queue,
    )
