from typing import List, Dict, Any
from core.models import Finding, Evidence
from core.correlation import ProcessEvidence


def detect_lateral_movement(correlation_map: Dict[int, ProcessEvidence]) -> List[Finding]:
    findings = []
    lateral_indicators = ["psexec", "wmic", "winrm", "smbclient", "net use", "invoke-command"]

    for pid, ev in correlation_map.items():
        cmdline = (ev.process.cmdline or "").lower()
        name = ev.process.name.lower()

        matches = [ind for ind in lateral_indicators if ind in cmdline or ind in name]
        if matches and ev.network_connections:
            findings.append(Finding(
                title=f"Potential Lateral Movement Indicator: {ev.process.name} (PID {pid})",
                description=f"Process associated with remote administration ({', '.join(matches)}) observed with {len(ev.network_connections)} network connections.",
                severity="medium",
                confidence=0.50,
                evidence=[Evidence(
                    source="detection_engine.lateral_movement",
                    artifact=f"PID {pid} cmdline + netscan",
                    confidence=0.50
                )],
                requires_validation=True,
                alternative_explanations=[
                    "Authorized administrative activity (e.g., IT department managing the endpoint)",
                    "Legitimate background service behavior for enterprise environments"
                ],
                inferences=[
                    f"If unauthorized, the attacker may be using {matches[0]} to move laterally or execute remote commands."
                ]
            ))
    return findings


def detect_persistence(correlation_map: Dict[int, ProcessEvidence]) -> List[Finding]:
    findings = []
    persistence_indicators = [
        "schtasks", "at.exe", "reg add", "sc create", "startup",
        "run /v", "runonce", "userinit", "winlogon"
    ]

    for pid, ev in correlation_map.items():
        cmdline = (ev.process.cmdline or "").lower()
        matches = [ind for ind in persistence_indicators if ind in cmdline]
        if matches:
            findings.append(Finding(
                title=f"Potential Persistence Indicator: {ev.process.name} (PID {pid})",
                description=f"Process contains keywords often associated with persistence mechanisms: {', '.join(matches)}.",
                severity="medium",
                confidence=0.45,
                evidence=[Evidence(
                    source="detection_engine.persistence",
                    artifact=f"PID {pid} cmdline",
                    confidence=0.45
                )],
                requires_validation=True,
                alternative_explanations=[
                    "Normal OS operations (e.g., winlogon.exe is a required system process)",
                    "Legitimate software installation or scheduled maintenance task"
                ],
                inferences=[
                    "Presence of keyword requires checking Registry Run keys, Scheduled Tasks, or Service creation artifacts to confirm persistence."
                ]
            ))
    return findings


def detect_credential_access(correlation_map: Dict[int, ProcessEvidence]) -> List[Finding]:
    findings = []
    cred_indicators = [
        "mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs.dll",
        "hashdump", "sam", "ntds.dit", "credential"
    ]

    for pid, ev in correlation_map.items():
        cmdline = (ev.process.cmdline or "").lower()
        name = ev.process.name.lower()
        matches = [ind for ind in cred_indicators if ind in cmdline or ind in name]
        if matches:
            # If it's literally mimikatz, confidence is higher. If it's just 'sam' or 'lsass', confidence is low.
            conf = 0.9 if "mimikatz" in matches else 0.40
            severity = "critical" if conf > 0.8 else "medium"
            
            alt_explanations = [
                "Legitimate authentication processes (e.g., lsass.exe naturally handles credentials)",
                "Coincidental substring match in command line or process name (e.g., 'sam' in 'sample.exe' or 'slack.exe' arguments)"
            ] if conf < 0.8 else ["Authorized penetration testing or red team activity"]
            
            findings.append(Finding(
                title=f"Potential Credential-Access Indicator: {ev.process.name} (PID {pid})",
                description=f"Observed keyword match for credential access tooling or targets: {', '.join(matches)}.",
                severity=severity,
                confidence=conf,
                evidence=[Evidence(
                    source="detection_engine.credential_access",
                    artifact=f"PID {pid} name/cmdline",
                    confidence=conf
                )],
                requires_validation=True,
                alternative_explanations=alt_explanations,
                inferences=[
                    "If malicious, the actor may be attempting to dump LSASS or SAM to harvest password hashes or tickets."
                ]
            ))
    return findings


def detect_ransomware(correlation_map: Dict[int, ProcessEvidence]) -> List[Finding]:
    findings = []
    ransom_indicators = [
        "vssadmin", "delete shadows", "bcdedit", "wbadmin",
        "recoveryenabled", "cipher /w", "readme.txt", "decrypt"
    ]

    for pid, ev in correlation_map.items():
        cmdline = (ev.process.cmdline or "").lower()
        matches = [ind for ind in ransom_indicators if ind in cmdline]
        if matches:
            findings.append(Finding(
                title=f"Potential Ransomware/Destruction Indicator: {ev.process.name} (PID {pid})",
                description=f"Process contains keywords associated with backup deletion or encryption: {', '.join(matches)}.",
                severity="high",
                confidence=0.60,
                evidence=[Evidence(
                    source="detection_engine.ransomware",
                    artifact=f"PID {pid} cmdline",
                    confidence=0.60
                )],
                requires_validation=True,
                alternative_explanations=[
                    "Legitimate system backup management or recovery software",
                    "Administrative script cleaning up old shadow copies"
                ],
                inferences=[
                    "Actors often delete Volume Shadow Copies to prevent file recovery before initiating ransomware encryption."
                ]
            ))
    return findings


def detect_lolbins(correlation_map: Dict[int, ProcessEvidence]) -> List[Finding]:
    findings = []
    lolbins = [
        "certutil", "mshta", "regsvr32", "rundll32", "wscript",
        "cscript", "msiexec", "installutil", "bitsadmin",
        "forfiles", "pcalua", "cmstp"
    ]

    for pid, ev in correlation_map.items():
        name = ev.process.name.lower().replace(".exe", "")
        cmdline = (ev.process.cmdline or "").lower()

        if name in lolbins:
            suspicious = False
            reasons = [f"Living-off-the-Land Binary (LOLBin) execution: {ev.process.name}"]

            if ev.network_connections:
                suspicious = True
                reasons.append(f"{len(ev.network_connections)} network connections")
            if ev.injections:
                suspicious = True
                reasons.append(f"{len(ev.injections)} injected memory regions")
            if "-enc" in cmdline or "http" in cmdline or "downloadstring" in cmdline:
                suspicious = True
                reasons.append("Suspicious command line arguments (e.g., remote download or encoding)")

            if suspicious:
                findings.append(Finding(
                    title=f"Potential LOLBin Abuse: {ev.process.name} (PID {pid})",
                    description=" | ".join(reasons),
                    severity="high",
                    confidence=0.65,
                    evidence=[Evidence(
                        source="detection_engine.lolbins",
                        artifact=f"PID {pid}",
                        confidence=0.65
                    )],
                    requires_validation=True,
                    alternative_explanations=[
                        "Legitimate OS or software update mechanism (e.g., bitsadmin/certutil downloading updates)",
                        "Normal script execution by system administrators"
                    ],
                    inferences=[
                        "Attackers use signed native binaries to bypass application whitelisting and hide malicious downloads/execution."
                    ]
                ))
    return findings


def run_all_detections(correlation_map: Dict[int, ProcessEvidence]) -> List[Finding]:
    findings = []
    findings.extend(detect_lateral_movement(correlation_map))
    findings.extend(detect_persistence(correlation_map))
    findings.extend(detect_credential_access(correlation_map))
    findings.extend(detect_ransomware(correlation_map))
    findings.extend(detect_lolbins(correlation_map))
    return findings
