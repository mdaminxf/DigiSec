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
classDef prompt fill:#eceff1,stroke:#37474f,stroke-width:2px,color:#37474f
classDef loader fill:#006064,stroke:#fff,stroke-width:2px,color:#fff
classDef llm fill:#4a148c,stroke:#fff,stroke-width:2px,color:#fff
classDef tools fill:#0d47a1,stroke:#fff,stroke-width:1px,color:#fff
classDef safe fill:#1b5e20,stroke:#fff,stroke-width:1px,color:#fff
classDef report fill:#b71c1c,stroke:#fff,stroke-width:2px,color:#fff
classDef storage fill:#37474f,stroke:#fff,stroke-width:2px,color:#fff,stroke-dasharray: 4 4

%% =========================
%% STEP 1: INITIALIZATION & ENTRY
%% =========================
subgraph S1 [1. INITIALIZATION & INGESTION]
    A([User Case Prompt]):::prompt -->|Case Parameters| B(Orchestrator AI Core):::llm
    Y1[tools_config.yaml]:::loader -->|Parse Runtime Specs| Y2(Dynamic Tool Loader):::loader
    Y2 -->|Register FastMCP Manifest| B
end

%% =========================
%% STEP 2: WORKSPACE & INTEGRITY LOCK
%% =========================
subgraph S2 [2. STORAGE BOUNDARY & IMMUTABILITY]
    B -->|Verify Sandbox Paths| Vault1[(Evidence Baseline Vault <br> Read-Only .e01 / .raw)]:::storage
    B -->|Initialize Non-Repudiation Trace| Vault2[(provenance_audit.jsonl Ledger)]:::safe
end

%% =========================
%% STEP 3: AUTONOMOUS PROCESSING & RECOVERY LOOP
%% =========================
subgraph S3 [3. FORENSIC PROCESSING & RECOVERY LOOP]
    B -->|Invoke| T1[Disk Tool: secure_ewf_mount]:::tools
    T1 -->|Proceed| T2[Disk Tool: safe_mmls]:::tools
    
    %% Dynamic Error & Self-Correction Feedback Loop
    T2 -.->|Geometry Trap: Status Error / Invalid Sector| B
    B -.->|Autonomous Self-Correction Pivot| T3[Disk Tool: mount_logical_ntfs]:::tools
    
    T3 -->|Hand off control| T4[Memory Tool: windows.netscan]:::tools
    T4 -->|Narrow boundaries| T5[Memory Tool: windows.cmdline / pslist]:::tools
    T5 -->|Route signatures| T6[Intel Tool: Reputation & MITRE Mapping]:::tools
end

%% Real-time Machine Metrics Log Link during loop
T1 & T2 & T3 & T4 & T5 & T6 -.->|Append Transaction Telemetry| Vault2

%% =========================
%% STEP 4: INTER-ARTIFACT CORRELATION ENGINE
%% =========================
subgraph S4 [4. INTER-ARTIFACT CORRELATION]
    T6 -->|Pass findings| C1[Stream Merger]
    C1 -->|Feed into| C2[Anomaly Validation Engine]
    C2 -->|Solidify into| C3[Extracted Technical Findings]
end

%% =========================
%% STEP 5: ASSURANCE DELIVERABLES & REPORTING
%% =========================
subgraph S5 [5. ASSURANCE DELIVERABLES]
    C3 -->|Initiate| R1[HTML Summary Interface Builder]
    R1 -->|Compile into| R2[Executive PDF Report Renderer]
    R2 -->|Export files into| Vault3[(case_rocba_final_report.md Archive)]:::report
    Vault3 --> H4([Final Case File Secured]):::report
end
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
