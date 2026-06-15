from typing import Dict, List, Optional, Any
from pydantic import BaseModel
from core.workspace import save_json


class GraphNode(BaseModel):
    """A node in the evidence graph representing a forensic entity."""
    node_id: str
    node_type: str  # process, file, user, registry_key, ip_address, domain, service
    label: str
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    """A relationship edge between two nodes in the evidence graph."""
    source: str
    target: str
    relationship: str  # executed, created, modified, connected_to, downloaded, uploaded, persisted_via, spawned, injected_into, authenticated_as
    timestamp: Optional[str] = None
    confidence: float = 1.0
    source_artifact: str = ""


class EvidenceGraphEngine:
    """Formal evidence graph engine for DFIR investigations.
    
    Builds and manages an interconnected graph of forensic entities
    and their relationships. Supports attack chain extraction and
    serialization to the case workspace.
    """

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []

    def add_node(self, node_id: str, node_type: str, label: str, properties: Dict[str, Any] = None):
        """Add or update a node in the evidence graph."""
        self.nodes[node_id] = GraphNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
        )

    def add_edge(self, source: str, target: str, relationship: str,
                 timestamp: str = None, confidence: float = 1.0, source_artifact: str = ""):
        """Add a relationship edge between two nodes."""
        # Prevent duplicate edges
        for existing in self.edges:
            if (existing.source == source and existing.target == target
                    and existing.relationship == relationship):
                return
        self.edges.append(GraphEdge(
            source=source,
            target=target,
            relationship=relationship,
            timestamp=timestamp,
            confidence=confidence,
            source_artifact=source_artifact,
        ))

    def add_process(self, pid: int, name: str, ppid: int = None,
                    cmdline: str = None, create_time: str = None):
        """Convenience method to add a process node."""
        self.add_node(
            node_id=f"proc_{pid}",
            node_type="process",
            label=name,
            properties={"pid": pid, "ppid": ppid, "cmdline": cmdline, "create_time": create_time},
        )
        # Add parent-child edge if parent exists
        if ppid and f"proc_{ppid}" in self.nodes:
            self.add_edge(f"proc_{ppid}", f"proc_{pid}", "spawned", timestamp=create_time)

    def add_network_connection(self, pid: int, remote_ip: str, remote_port: int,
                                protocol: str = "TCP"):
        """Convenience method to add a network connection."""
        ip_id = f"ip_{remote_ip}"
        self.add_node(
            node_id=ip_id,
            node_type="ip_address",
            label=remote_ip,
            properties={"port": remote_port, "protocol": protocol},
        )
        self.add_edge(f"proc_{pid}", ip_id, "connected_to", source_artifact="netscan")

    def add_file(self, filepath: str, properties: Dict[str, Any] = None):
        """Convenience method to add a file node."""
        import hashlib
        file_id = f"file_{hashlib.md5(filepath.encode()).hexdigest()[:8]}"
        self.add_node(
            node_id=file_id,
            node_type="file",
            label=filepath,
            properties=properties or {},
        )
        return file_id

    def add_registry_key(self, key_path: str, properties: Dict[str, Any] = None):
        """Convenience method to add a registry key node."""
        import hashlib
        key_id = f"reg_{hashlib.md5(key_path.encode()).hexdigest()[:8]}"
        self.add_node(
            node_id=key_id,
            node_type="registry_key",
            label=key_path,
            properties=properties or {},
        )
        return key_id

    def get_neighbors(self, node_id: str) -> List[Dict[str, Any]]:
        """Get all nodes connected to a given node."""
        neighbors = []
        for edge in self.edges:
            if edge.source == node_id:
                neighbor = self.nodes.get(edge.target)
                if neighbor:
                    neighbors.append({
                        "node": neighbor.model_dump(),
                        "relationship": edge.relationship,
                        "direction": "outgoing",
                        "confidence": edge.confidence,
                    })
            elif edge.target == node_id:
                neighbor = self.nodes.get(edge.source)
                if neighbor:
                    neighbors.append({
                        "node": neighbor.model_dump(),
                        "relationship": edge.relationship,
                        "direction": "incoming",
                        "confidence": edge.confidence,
                    })
        return neighbors

    def get_attack_chains(self) -> List[List[Dict[str, Any]]]:
        """Extract attack chains using DFS from root nodes."""
        chains = []
        visited = set()

        def dfs(node_id: str, current_chain: list):
            if node_id in visited:
                return
            visited.add(node_id)
            node = self.nodes.get(node_id)
            if node:
                current_chain.append(node.model_dump())
            for edge in self.edges:
                if edge.source == node_id:
                    dfs(edge.target, current_chain)

        # Find root nodes (no incoming edges)
        for node_id in self.nodes:
            is_root = not any(e.target == node_id for e in self.edges)
            if is_root and node_id not in visited:
                chain = []
                dfs(node_id, chain)
                if len(chain) > 1:
                    chains.append(chain)

        return chains

    def get_stats(self) -> Dict[str, Any]:
        """Get summary statistics of the evidence graph."""
        type_counts = {}
        for node in self.nodes.values():
            type_counts[node.node_type] = type_counts.get(node.node_type, 0) + 1

        rel_counts = {}
        for edge in self.edges:
            rel_counts[edge.relationship] = rel_counts.get(edge.relationship, 0) + 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": type_counts,
            "relationship_types": rel_counts,
            "attack_chains": len(self.get_attack_chains()),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the entire graph to a dictionary."""
        return {
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges],
            "attack_chains": self.get_attack_chains(),
            "stats": self.get_stats(),
        }

    def persist(self):
        """Save the evidence graph to the case workspace."""
        save_json(self.case_id, "graph", "evidence_graph.json", self.to_dict())
