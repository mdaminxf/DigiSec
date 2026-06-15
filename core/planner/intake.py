import os
from typing import List, Tuple
from core.models.case import EvidenceItem, EvidenceType, CaseType


EVIDENCE_EXTENSIONS = {
    ".raw": EvidenceType.MEMORY_IMAGE,
    ".mem": EvidenceType.MEMORY_IMAGE,
    ".vmem": EvidenceType.MEMORY_IMAGE,
    ".dmp": EvidenceType.MEMORY_IMAGE,
    ".e01": EvidenceType.DISK_IMAGE,
    ".E01": EvidenceType.DISK_IMAGE,
    ".dd": EvidenceType.DISK_IMAGE,
    ".img": EvidenceType.DISK_IMAGE,
    ".vhd": EvidenceType.DISK_IMAGE,
    ".vhdx": EvidenceType.DISK_IMAGE,
    ".evtx": EvidenceType.EVTX_FILE,
    ".pcap": EvidenceType.PCAP,
    ".pcapng": EvidenceType.PCAP,
}

REGISTRY_HIVE_NAMES = {
    "system", "software", "sam", "security", "ntuser.dat",
    "usrclass.dat", "amcache.hve", "default"
}

CASE_TYPE_KEYWORDS = {
    CaseType.IP_THEFT: [
        "theft", "stolen", "intellectual property", "ip theft", "exfiltrat",
        "trade secret", "proprietary", "confidential data", "data loss",
        "usb", "cloud", "onedrive", "sharepoint", "upload"
    ],
    CaseType.RANSOMWARE: [
        "ransomware", "encrypted", "ransom", "decrypt", "bitcoin",
        "locked files", ".locked", "crypto", "payment"
    ],
    CaseType.INSIDER_THREAT: [
        "insider", "employee", "terminated", "disgruntled", "resignation",
        "unauthorized access", "privilege abuse", "data hoarding"
    ],
    CaseType.MALWARE: [
        "malware", "infection", "trojan", "virus", "worm", "backdoor",
        "c2", "command and control", "beacon", "cobalt", "meterpreter"
    ],
}


def discover_evidence(paths: List[str]) -> List[EvidenceItem]:
    """Discover and classify all evidence items from the provided file paths.
    
    Examines file extensions and names to determine evidence types.
    Verifies files exist and records their sizes.
    """
    items = []
    for path in paths:
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            continue

        if os.path.isdir(path):
            # Check if it's a prefetch directory
            pf_files = [f for f in os.listdir(path) if f.lower().endswith(".pf")]
            if pf_files:
                items.append(EvidenceItem(
                    path=path,
                    evidence_type=EvidenceType.PREFETCH_DIR,
                    size_bytes=sum(os.path.getsize(os.path.join(path, f)) for f in pf_files),
                    verified=True,
                    description=f"Prefetch directory with {len(pf_files)} .pf files"
                ))
            else:
                # Recurse into directory looking for evidence files
                for root, _, files in os.walk(path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        sub_items = discover_evidence([fpath])
                        items.extend(sub_items)
        else:
            ext = os.path.splitext(path)[1].lower()
            basename = os.path.basename(path).lower()
            size = os.path.getsize(path)

            if ext in EVIDENCE_EXTENSIONS:
                items.append(EvidenceItem(
                    path=path,
                    evidence_type=EVIDENCE_EXTENSIONS[ext],
                    size_bytes=size,
                    verified=True,
                    description=f"{EVIDENCE_EXTENSIONS[ext].value}: {os.path.basename(path)}"
                ))
            elif basename in REGISTRY_HIVE_NAMES:
                items.append(EvidenceItem(
                    path=path,
                    evidence_type=EvidenceType.REGISTRY_HIVE,
                    size_bytes=size,
                    verified=True,
                    description=f"Registry hive: {basename}"
                ))

    return items


def classify_case(description: str, evidence: List[EvidenceItem]) -> CaseType:
    """Classify the case type based on the description and available evidence.
    
    Uses keyword matching against the case description to determine
    the most likely investigation type.
    """
    if not description:
        return CaseType.INCIDENT_RESPONSE

    desc_lower = description.lower()
    scores = {ct: 0 for ct in CaseType}

    for case_type, keywords in CASE_TYPE_KEYWORDS.items():
        for keyword in keywords:
            if keyword in desc_lower:
                scores[case_type] += 1

    best = max(scores, key=scores.get)
    if scores[best] > 0:
        return best

    return CaseType.INCIDENT_RESPONSE
