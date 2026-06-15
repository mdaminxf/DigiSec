# Extensible DFIR MCP Platform (Protocol SIFT)

> **SANS Hackathon Submission**
> 
> *An autonomous, zero-spoliation digital forensics platform. Wrap SIFT's tools into a type-safe MCP server, execute multi-source correlation, dynamically load zero-code YAML extensions, and output courtroom-ready PDF reports.*

---

## 🏆 Hackathon Ideas Implemented
This architecture natively solves several of the hardest problems in AI-assisted DFIR:

1. **The Purpose-Built MCP Server (Zero Spoliation):** LLMs do not get raw bash access. They must route through our FastMCP server. Disk evidence is safely exposed via `mount_e01_image` which enforces OS-level `ntfs-3g ro,loop` read-only mounts. Evidence cannot be modified.
2. **The Self-Correcting Triage Agent (Anti-Hallucination):** The Detection Engine heuristics strictly enforce the DFIR standard of *Observed Fact → Evidence → Inference → Conclusion*. Findings natively return `requires_validation=True` and `alternative_explanations` to prevent the AI from jumping to speculative conclusions.
3. **Multi-Source Correlation Engine:** Seamlessly merges memory extraction (Volatility 3) and disk artifacts ($MFT, Prefetch, Evtx) into unified timelines.
4. **Zero-Code Extensibility:** The Dynamic Plugin Loader instantly compiles any `.yaml` or `.py` files dropped into the `plugins/` directory into type-safe AI tools without requiring server restarts.

## 🏗 Architecture

The platform acts as an unbreachable wall between the AI and the raw evidence, guaranteeing chain-of-custody integrity while granting the LLM massive analytical power.

```mermaid
graph LR

%% Styles
classDef llm fill:#4a148c,stroke:#fff,stroke-width:2px,color:#fff
classDef tools fill:#0d47a1,stroke:#fff,stroke-width:1px,color:#fff
classDef safe fill:#1b5e20,stroke:#fff,stroke-width:1px,color:#fff
classDef report fill:#b71c1c,stroke:#fff,stroke-width:2px,color:#fff
classDef isolate fill:#f57f17,stroke:#fff,stroke-width:2px,color:#fff

%% Root: The investigation starts with a single natural language prompt
A([Analyst Mega-Prompt]) --> B[AI Orchestrator]:::llm

%% FIRST CALL LAYER: The AI dynamically routes to the major tool boundaries
B --> C1[Evidence Isolation]:::isolate
B --> C2[Threat Intelligence]:::tools
B --> C3[Disk Forensics]:::tools

%% SECOND CALL LAYER: Sub-tasks handled autonomously by the tools
C1 --> D1[Scope Definition]
C1 --> D2[Case Segregation]

C3 --> D3[Read-Only Mount]
C3 --> D4[MFT & Prefetch Extraction]
C3 --> D5[File Normalization]

C2 --> D6[IOC Lookup]
C2 --> D7[Reputation Check]
C2 --> D8[MITRE Mapping]

%% THIRD LAYER: Derived Outputs constrained by safety rules
D3 --> E1[Disk Evidence Output]:::safe
D4 --> E1
D5 --> E1

D6 --> E2[Threat Context Output]:::safe
D7 --> E2
D8 --> E2

%% Isolated evidence feeds safely into memory extraction
C1 --> E3[Memory Forensics]:::tools
E3 --> F1[Memory Snapshot]
E3 --> F2[Process Extraction]
E3 --> F3[Network Mapping]

F1 --> E4[Process Tree Output]:::safe
F2 --> E4
F3 --> E4

%% FOURTH LAYER: The Anti-Hallucination Correlation Engine
B --> G[Correlation Engine]:::safe
E1 --> G
E2 --> G
E4 --> G

G --> G1[Merge Evidence]
G --> G2[Anomaly Detection]
G --> G3[Validation Check]
G --> G4[DFIR Findings]

%% FINAL LAYER: Compiling the findings into the Executive PDF
G --> H[Report Generation]:::report
H --> H1[Structuring]
H --> H2[Executive Summary]
H --> H3[WeasyPrint Render]
H --> H4([Final Courtroom-Ready PDF])
```

## 🚀 Setup & Execution

### 1. Requirements
* Python 3.14+
* `ewf-tools` and `ntfs-3g` (for `.e01` disk mounting)
* `weasyprint` (for PDF generation)

### 2. Run the Server
The environment is pre-configured. Start the FastMCP server:
```bash
source venv/bin/activate
python server.py
```

### 3. Claude Desktop Configuration
Add the server to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "sift-dfir-mcp": {
      "command": "/home/sansforensics/Desktop/sift-mcp/venv/bin/python",
      "args": [
        "/home/sansforensics/Desktop/sift-mcp/server.py"
      ]
    }
  }
}
```

## 🧩 Adding New Tools (Zero-Code YAML)
You do not need to know Python to extend this platform. Simply drop a `.yaml` file into the `plugins/` directory.

Example `plugins/network/check_ip.yaml`:
```yaml
name: check_ip_reputation
description: "Checks the reputation of an IP address using curl."
arguments:
  ip_address:
    type: str
command: "curl -s 'https://api.threatintel.com/ip/{ip_address}'"
```
The server will dynamically generate a Python tool, inject the arguments safely, and register it with the AI automatically.

## 📄 Executive PDF Reporting
To prevent massive walls of unreadable text in the chat interface, the platform includes a WeasyPrint renderer (`plugins/analysis/custom_report.py`). The LLM will automatically generate elegant, styled HTML and compile it into a confidential PDF document saved directly to your workspace.

# DigiSec
