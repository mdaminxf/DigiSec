from typing import List, Dict, Any
from core.models import Finding

ATTACK_KNOWLEDGE = {
    "credential_access": {
        "description": "Credential access involves stealing credentials such as account names and passwords.",
        "mitre_id": "TA0006",
        "common_tools": ["mimikatz", "procdump", "comsvcs.dll"],
        "artifacts_to_check": ["LSASS memory", "SAM hive", "Security event logs", "NTDS.dit"],
        "investigation_steps": [
            "1. Check for LSASS access in memory (handles, injections)",
            "2. Look for procdump or comsvcs.dll in command lines",
            "3. Check Security event log for Event ID 4624/4625",
            "4. Verify SAM/SYSTEM hive access in MFT timeline",
            "5. Check for credential dumping tool artifacts in prefetch"
        ]
    },
    "lateral_movement": {
        "description": "Lateral movement consists of techniques that adversaries use to enter and control remote systems.",
        "mitre_id": "TA0008",
        "common_tools": ["psexec", "wmic", "winrm", "RDP"],
        "artifacts_to_check": ["Security event logs", "Network connections", "Service creation", "Prefetch"],
        "investigation_steps": [
            "1. Identify remote logon events (Event IDs 4624 Type 3/10)",
            "2. Check network connections for SMB/RDP/WinRM ports",
            "3. Look for PsExec service creation in System event log",
            "4. Verify remote access tool artifacts in prefetch",
            "5. Correlate timestamps between source and target systems"
        ]
    },
    "persistence": {
        "description": "Persistence consists of techniques that adversaries use to keep access to systems across restarts.",
        "mitre_id": "TA0003",
        "common_tools": ["schtasks", "reg.exe", "sc.exe", "startup folder"],
        "artifacts_to_check": ["Registry run keys", "Scheduled tasks", "Services", "Startup folder"],
        "investigation_steps": [
            "1. Check registry Run/RunOnce keys",
            "2. Examine scheduled tasks in registry and task XML files",
            "3. Look for new or modified services",
            "4. Check Startup folder for suspicious entries",
            "5. Verify WMI event subscriptions"
        ]
    },
    "code_injection": {
        "description": "Process injection involves running code in the address space of another process.",
        "mitre_id": "T1055",
        "common_tools": ["reflective DLL", "process hollowing", "APC injection"],
        "artifacts_to_check": ["Malfind output", "VAD analysis", "DLL list comparison"],
        "investigation_steps": [
            "1. Run malfind to detect RWX memory regions",
            "2. Compare DLL list with known good baselines",
            "3. Analyze VAD entries for suspicious allocations",
            "4. Extract and hash injected code for YARA/VT scanning",
            "5. Check parent process for injection capabilities"
        ]
    },
    "ransomware": {
        "description": "Ransomware encrypts victim files and demands payment for decryption.",
        "mitre_id": "T1486",
        "common_tools": ["vssadmin", "bcdedit", "wbadmin", "cipher"],
        "artifacts_to_check": ["Shadow copy deletion", "Boot config changes", "File system changes", "Ransom notes"],
        "investigation_steps": [
            "1. Check for vssadmin delete shadows in command lines",
            "2. Look for bcdedit recovery disable commands",
            "3. Analyze MFT for mass file modifications",
            "4. Check for ransom note file creation",
            "5. Identify the encryption process and its network beaconing"
        ]
    }
}


def explain_finding(finding: Finding) -> Dict[str, Any]:
    title_lower = finding.title.lower()
    description_lower = finding.description.lower()
    combined = title_lower + " " + description_lower

    matched_category = None
    for category, knowledge in ATTACK_KNOWLEDGE.items():
        category_terms = category.replace("_", " ")
        if category_terms in combined:
            matched_category = category
            break
        for tool in knowledge["common_tools"]:
            if tool.lower() in combined:
                matched_category = category
                break
        if matched_category:
            break

    if not matched_category:
        return {
            "finding": finding.title,
            "explanation": "No specific attack category matched.",
            "recommendation": "Review the evidence manually and correlate with other findings."
        }

    knowledge = ATTACK_KNOWLEDGE[matched_category]
    return {
        "finding": finding.title,
        "category": matched_category,
        "mitre_attack_id": knowledge["mitre_id"],
        "explanation": knowledge["description"],
        "reasoning": [ev.artifact for ev in finding.evidence],
        "common_tools": knowledge["common_tools"],
        "artifacts_to_check": knowledge["artifacts_to_check"],
        "investigation_steps": knowledge["investigation_steps"]
    }
