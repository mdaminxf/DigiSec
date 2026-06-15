from typing import List, Dict, Any
from core.models import Process, Finding, Evidence
from core.models.disk import PrefetchEntry, AmcacheEntry, ShimcacheEntry


def correlate_memory_disk(
    processes: List[Process],
    prefetch: List[PrefetchEntry] = None,
    amcache: List[AmcacheEntry] = None,
    shimcache: List[ShimcacheEntry] = None
) -> List[Dict[str, Any]]:

    prefetch = prefetch or []
    amcache = amcache or []
    shimcache = shimcache or []

    prefetch_exes = {p.executable.lower() for p in prefetch}
    amcache_paths = {a.filepath.lower() for a in amcache}
    shimcache_paths = {s.filepath.lower() for s in shimcache}

    correlations = []

    for proc in processes:
        proc_name = proc.name.lower()

        in_prefetch = any(proc_name in exe for exe in prefetch_exes)
        in_amcache = any(proc_name in path for path in amcache_paths)
        in_shimcache = any(proc_name in path for path in shimcache_paths)

        disk_evidence_count = sum([in_prefetch, in_amcache, in_shimcache])

        if disk_evidence_count == 0:
            correlations.append({
                "pid": proc.pid,
                "process": proc.name,
                "memory_only": True,
                "disk_evidence_count": 0,
                "assessment": "memory-only execution / possible anti-forensics",
                "confidence": 0.7,
                "in_prefetch": False,
                "in_amcache": False,
                "in_shimcache": False
            })
        else:
            correlations.append({
                "pid": proc.pid,
                "process": proc.name,
                "memory_only": False,
                "disk_evidence_count": disk_evidence_count,
                "assessment": "corroborated by disk artifacts",
                "confidence": min(0.5 + disk_evidence_count * 0.2, 1.0),
                "in_prefetch": in_prefetch,
                "in_amcache": in_amcache,
                "in_shimcache": in_shimcache
            })

    return correlations
