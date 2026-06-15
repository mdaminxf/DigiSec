# Extensible DFIR MCP Platform (DigiSec)

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

%% =========================
%% ROOT
%% =========================
A([Prompt])-->B[Orchestrator]:::llm

%% =========================
%% TOOLS FRAME
%% =========================
subgraph T[TOOLS]
direction TB
C1[Isolation]:::isolate
C2[Intel]:::tools
C3[Disk]:::tools
C4[Memory]:::tools
end

B-->C1
B-->C2
B-->C3
B-->C4

%% =========================
%% ISOLATION FRAME
%% =========================
subgraph I[ISOLATION]
direction TB
D1[Scope]
D2[Case]
end

C1-->D1
C1-->D2

%% =========================
%% DISK FRAME
%% =========================
subgraph D[DISK]
direction TB
D3[Mount]-->D4[MFT]-->D5[Norm]-->E1[DiskOut]:::safe
end

C3-->D3

%% =========================
%% MEMORY FRAME
%% =========================
subgraph M[MEM]
direction TB
D6[Snap]-->D7[Proc]-->D8[Net]-->E2[MemOut]:::safe
end

C4-->D6

%% =========================
%% INTEL FRAME
%% =========================
subgraph TI[INTEL]
direction TB
D9[IOC]-->D10[Rep]-->D11[MITRE]-->E3[IntelOut]:::safe
end

C2-->D9

%% =========================
%% CORRELATION FRAME
%% =========================
subgraph C[CORR]
direction TB
E1-->G[Merge]
E2-->G
E3-->G
G-->G1[Anom]-->G2[Valid]-->G3[Find]
end

%% =========================
%% REPORT FRAME
%% =========================
subgraph R[REPORT]
direction TB
H1[Struct]-->H2[Sum]-->H3[Render]-->H4([Final]):::report
end

G3-->H1
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
