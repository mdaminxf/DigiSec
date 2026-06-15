from core.models import Process, NetworkConnection, InjectedRegion
from typing import List, Dict

class ProcessEvidence:
    def __init__(self, process: Process):
        self.process = process
        self.network_connections: List[NetworkConnection] = []
        self.injections: List[InjectedRegion] = []
        self.hidden: bool = False

def correlate_artifacts(
    processes: List[Process], 
    network: List[NetworkConnection], 
    injections: List[InjectedRegion],
    hidden_pids: List[int]
) -> Dict[int, ProcessEvidence]:
    
    correlation_map = {p.pid: ProcessEvidence(p) for p in processes}
    
    for conn in network:
        if conn.pid in correlation_map:
            correlation_map[conn.pid].network_connections.append(conn)
            
    for inj in injections:
        if inj.pid in correlation_map:
            correlation_map[inj.pid].injections.append(inj)

    for pid in hidden_pids:
        if pid in correlation_map:
            correlation_map[pid].hidden = True
            
    return correlation_map
