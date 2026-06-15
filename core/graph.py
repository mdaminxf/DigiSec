from typing import Dict, List, Optional, Any
from pydantic import BaseModel


class GraphNode(BaseModel):
    node_id: str
    node_type: str  # process, file, network, registry
    label: str
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str  # executed, created, connected_to, modified, loaded
    timestamp: Optional[str] = None
    confidence: float = 1.0


class EvidenceGraph:
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []

    def add_node(self, node_id: str, node_type: str, label: str, properties: Dict[str, Any] = {}):
        self.nodes[node_id] = GraphNode(
            node_id=node_id, node_type=node_type, label=label, properties=properties
        )

    def add_edge(self, source: str, target: str, relationship: str, timestamp: str = None, confidence: float = 1.0):
        self.edges.append(GraphEdge(
            source=source, target=target, relationship=relationship,
            timestamp=timestamp, confidence=confidence
        ))

    def get_neighbors(self, node_id: str) -> List[Dict[str, Any]]:
        neighbors = []
        for edge in self.edges:
            if edge.source == node_id:
                neighbor = self.nodes.get(edge.target)
                if neighbor:
                    neighbors.append({
                        "node": neighbor.model_dump(),
                        "relationship": edge.relationship,
                        "confidence": edge.confidence
                    })
            elif edge.target == node_id:
                neighbor = self.nodes.get(edge.source)
                if neighbor:
                    neighbors.append({
                        "node": neighbor.model_dump(),
                        "relationship": edge.relationship,
                        "confidence": edge.confidence
                    })
        return neighbors

    def get_attack_chains(self) -> List[List[Dict[str, Any]]]:
        chains = []
        visited = set()

        def dfs(node_id, current_chain):
            if node_id in visited:
                return
            visited.add(node_id)
            node = self.nodes.get(node_id)
            if node:
                current_chain.append(node.model_dump())
            for edge in self.edges:
                if edge.source == node_id:
                    dfs(edge.target, current_chain)

        for node_id in self.nodes:
            is_root = not any(e.target == node_id for e in self.edges)
            if is_root and node_id not in visited:
                chain = []
                dfs(node_id, chain)
                if len(chain) > 1:
                    chains.append(chain)

        return chains

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.model_dump() for n in self.nodes.values()],
            "edges": [e.model_dump() for e in self.edges],
            "attack_chains": self.get_attack_chains()
        }
