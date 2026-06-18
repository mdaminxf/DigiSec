# Extensible DFIR MCP Platform (DigiSec)

![logo](https://github.com/mdaminxf/DigiSec/blob/bcbd2a0c921706a0ae4b709a4c1f36aeb7c16b51/logo.png)

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

%% =========================
%% STYLES
%% =========================
classDef llm fill:#4a148c,stroke:#fff,stroke-width:2px,color:#fff
classDef tools fill:#0d47a1,stroke:#fff,stroke-width:1px,color:#fff
classDef safe fill:#1b5e20,stroke:#fff,stroke-width:1px,color:#fff
classDef report fill:#b71c1c,stroke:#fff,stroke-width:2px,color:#fff
classDef isolate fill:#f57f17,stroke:#fff,stroke-width:2px,color:#fff
classDef storage fill:#37474f,stroke:#fff,stroke-width:2px,color:#fff,stroke-dasharray: 5 5
classDef loader fill:#006064,stroke:#fff,stroke-width:2px,color:#fff

%% =========================
%% SYSTEM INITIALIZATION & ROOT
%% =========================
Y1[tools_config.yaml]:::loader -->|1. Parse Specs| Y2(Dynamic Tool Loader):::loader
Y2 -->|2. Register FastMCP Manifest| B[Orchestrator]:::llm
A([User Prompt]) --> B

%% =========================
%% TOOLS FRAME
%% =========================
subgraph T[TOOLS ENGINE]
direction TB
C1[Isolation]:::isolate
C2[Intel]:::tools
C3[Disk]:::tools
C4[Memory]:::tools
end

B -->|3. Autonomous Trigger| T

%% =========================
%% DETAILED ENGINE SUBGRAPHS
%% =========================
subgraph I[ISOLATION]
direction TB
D1[Scope] --> D2[Case Space]
end
C1 --> D1

subgraph D[DISK COMPONENT]
direction TB
D3[Mount] --> D4[MFT Parser] --> D5[Timeline Norm] --> E1[DiskOut]:::safe
end
C3 --> D3

subgraph M[MEMORY COMPONENT]
direction TB
D6[Snapshot Info] --> D7[Process Tree] --> D8[Network Sockets] --> E2[MemOut]:::safe
end
C4 --> D6

subgraph TI[INTEL COMPONENT]
direction TB
D9[IOC Extraction] --> D10[Reputation Check] --> D11[MITRE Mapping] --> E3[IntelOut]:::safe
end
C2 --> D9

%% =========================
%% 🔄 THE AUTONOMOUS FEEDBACK & SELF-CORRECTION LOOP
%% =========================
E1 -.->|Error/Telemetry Payload| B
E2 -.->|Missing Dependencies/PIDs| B
E3 -.->|Intel Signatures| B
%% Meaning: This explicit feedback loop allows the AI to parse raw stderr/results and determine the next execution boundary completely hands-free.

%% =========================
%% CORRELATION FRAME
%% =========================
subgraph C[CORRELATION ENGINE]
direction TB
E1 --> G[Merge Streams]
E2 --> G
E3 --> G
G --> G1[Anomaly Detection] --> G2[Validation] --> G3[Extracted Findings]
end

%% =========================
%% REPORT FRAME
%% =========================
subgraph R[REPORT GENERATOR]
direction TB
H1[HTML Structure] --> H2[Executive Summary] --> H3[PDF Renderer] --> H4([Final PDF Report]):::report
end
G3 --> H1

%% =========================
%% 💾 THE SECURE SECURE STORAGE VAULT (PERSISTENCE LAYER)
%% =========================
subgraph ST[PERSISTENT FORENSIC VAULT]
direction TB
S1[(/Desktop/ Evidence Baseline <br> .e01 / .raw)]
S2[(provenance_audit.jsonl <br> Cryptographic Trace Log)]:::safe
S3[(case_rocba_final_report.md <br> Artifact Storage Cache)]:::report
end

%% Storage Data Flow Links
T -.->|Strict Non-Spoliation Read| S1
T -.->|Real-time Machine Metrics Log| S2
R -->|Export Deliverables| S3
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
    "digisec-mcp-server": {
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
