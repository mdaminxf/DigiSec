from typing import List, Dict, Any
from core.models import Process
from .pslist import parse_pslist

def parse_psscan(data: List[Dict[str, Any]], os_name: str) -> List[Process]:
    return parse_pslist(data, os_name)
