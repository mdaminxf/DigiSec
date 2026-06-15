import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from server import start_investigation

evidence_paths = [
    "/home/sansforensics/Desktop/Rocba-Memory/Rocba-Memory/Rocba-Memory.raw",
    "/home/sansforensics/Desktop/rocba-cdrive.e01"
]
desc = "Fred Rocba is a new employee... surface targeted... intellectual property stolen..."

plan = start_investigation(evidence_paths, desc)
import json
print(json.dumps(plan, indent=2))
