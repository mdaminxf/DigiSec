from typing import List, Dict, Any
from core.models import RegistryArtifact

def parse_registry(data: List[Dict[str, Any]]) -> List[RegistryArtifact]:
    entries = []
    for item in data:
        entries.append(RegistryArtifact(
            hive=item.get("Hive", ""),
            key_path=item.get("KeyPath", ""),
            value_name=item.get("ValueName", None),
            value_data=item.get("ValueData", None),
            last_modified=str(item.get("LastModified", ""))
        ))
    return entries
