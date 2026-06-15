import os
import glob
import re

DESCRIPTIONS = {
    "get_processes": '    """Extracts and parses the active process list from a memory image. Use this to identify running executables and their basic attributes."""',
    "get_process_tree": '    """Generates a hierarchical parent-child process tree from memory. Use this to visualize process lineage and spot anomalous child processes (e.g., cmd.exe spawned by word.exe)."""',
    "find_hidden_processes": '    """Cross-references the active process linked list (pslist) against memory pool allocations (psscan) to detect rootkit-hidden or unlinked processes."""',
    "get_network_connections": '    """Extracts active and terminated network connections from memory. Use this to identify external C2 beaconing, lateral movement, or reverse shells."""',
    "detect_code_injection": '    """Scans memory for injected code, hollowed processes, and RWX memory regions (malfind). Crucial for detecting fileless malware and in-memory payloads."""',
    "memory_triage": '    """Performs a rapid triage of a memory image, correlating processes, network connections, and code injections to return a prioritized list of high-risk suspicious processes."""',
    "generate_memory_report": '    """Generates a comprehensive, executive-level PDF forensic report of a memory image, saving it directly to the case workspace."""',
    "get_mft_timeline": '    """Parses the NTFS Master File Table ($MFT) to reconstruct file creation, modification, and deletion timelines."""',
    "get_prefetch": '    """Analyzes Windows Prefetch files to determine the execution history of applications, including execution counts and timestamps."""',
    "get_amcache": '    """Parses the Amcache.hve registry hive to uncover evidence of recently executed applications and their SHA1 hashes."""',
    "get_shimcache": '    """Extracts Application Compatibility Cache (Shimcache) entries to determine if an executable was run on the system."""',
    "get_event_logs": '    """Parses Windows Event Logs (EVTX) to identify logins, service creation, scheduled tasks, and lateral movement."""',
    "get_registry_artifacts": '    """Extracts critical forensic artifacts from Windows Registry hives (e.g., persistence mechanisms in Run keys)."""',
    "build_evidence_graph": '    """Constructs an interconnected Evidence Graph mapping the relationships between processes, files, registry keys, and network connections to reveal attack chains."""',
    "correlate_memory_disk_artifacts": '    """Cross-correlates running memory processes against disk artifacts (Prefetch/Amcache) to identify memory-only execution and anti-forensics."""',
    "build_attack_timeline": '    """Merges memory, disk, and event log artifacts into a single unified chronological attack timeline, highlighting temporal anomalies."""',
    "run_detection_engine": '    """Executes the heuristic detection engine against correlated artifacts to identify Lateral Movement, Persistence, Credential Access, and Ransomware behavior."""',
    "investigate": '    """The autonomous Self-Correcting DFIR Agent. Automatically orchestrates all memory/disk plugins, correlates data, runs detections, and highlights missing evidence gaps."""',
    "explain_findings": '    """Maps identified forensic findings to MITRE ATT&CK categories and provides educational explanations and investigation next steps for analysts."""',
    "run_benchmark": '    """Executes a forensic baseline benchmark against a known ground-truth dataset to calculate True Positive / False Positive rates and evaluate agent accuracy."""',
    "get_benchmark_history": '    """Retrieves the historical accuracy scores (Precision/Recall/F1) to track the agent\'s performance improvements over time."""',
    "record_investigation": '    """Records the results of a completed investigation into the Persistent Learning Loop to help the agent learn from missed findings or false positives."""',
    "get_learning_insights": '    """Analyzes the Persistent Learning Loop database to provide insights on commonly missed attacker techniques and frequent false positives."""',
}

def patch_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # We look for: def function_name(...):
    # If the next line isn't already a docstring, we inject it.
    
    modified = False
    lines = content.split('\n')
    new_lines = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        new_lines.append(line)
        
        match = re.match(r'^def ([a-zA-Z0-9_]+)\(', line)
        if match:
            func_name = match.group(1)
            if func_name in DESCRIPTIONS:
                # Check if next line is a docstring
                if i + 1 < len(lines) and '"""' in lines[i+1]:
                    pass # already has docstring
                else:
                    new_lines.append(DESCRIPTIONS[func_name])
                    modified = True
        i += 1
        
    if modified:
        with open(filepath, 'w') as f:
            f.write('\n'.join(new_lines))
        print(f"Patched {filepath}")

if __name__ == "__main__":
    for root, _, files in os.walk("plugins"):
        for file in files:
            if file.endswith(".py"):
                patch_file(os.path.join(root, file))
