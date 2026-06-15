## 💡 Inspiration
The integration of Artificial Intelligence into cybersecurity is moving at lightning speed, but **Digital Forensics and Incident Response (DFIR)** has largely been left behind. Why? Because of one non-negotiable rule in forensics: **Zero Spoliation**. 

If you give an LLM raw bash access to a machine to analyze an image, it might accidentally modify a file, alter a timestamp, or execute a payload—instantly rendering the evidence inadmissible in a court of law. Furthermore, LLMs tend to hallucinate when reading raw, unstructured hex or memory dumps. We were inspired to bridge this gap. We wanted to build an "unbreachable wall" between the AI's analytical power and the raw evidence, allowing the AI to act as an expert forensic analyst while strictly adhering to courtroom standards.

## ⚙️ What it does
**DigiSec** is an autonomous, self-correcting DFIR agent powered by the Model Context Protocol (MCP). Instead of giving the AI a generic bash terminal, we provide it with a strict set of forensic tools that enforce evidence integrity. 

- **Zero-Spoliation Evidence Ingestion:** When the AI is asked to mount an EnCase `E01` disk image, the server forces an OS-level read-only (`ro,noexec,loop`) mount. 
- **Autonomous Correlation:** DigiSec doesn't just read data; it actively cross-references volatile memory artifacts (via Volatility 3) against disk footprints (MFT, Prefetch) to uncover file-less malware and hidden persistence.
- **Automated Threat Intel:** It parses network sockets from memory and dynamically checks IP reputations.
- **Courtroom-Ready Reporting:** Instead of outputting chaotic JSON, the agent structures its findings and renders an elegant, executive-level PDF report.

## 🛠️ How we built it
We built the core infrastructure using **Python** and a **FastMCP server**. 
1. **The Wrapper Layer:** We wrapped industry-standard SIFT Workstation tools (`ewfmount`, `ntfs-3g`, `Volatility 3`) inside typed Python functions. 
2. **Forensic Guardrails:** We engineered a strict path-traversal defense system (`validate_path_security`) that ensures the AI cannot escape the designated case workspace. 
3. **Zero-Code Extensibility:** We implemented a dynamic plugin loader. Anyone can drop a simple `.yaml` file into the `plugins/` directory (e.g., to add a new `curl` threat intel lookup), and the server will instantly compile it into a type-safe MCP tool without requiring a restart.

## 🚧 Challenges we ran into
Our biggest challenge was handling edge cases where automated ingestion fails—a common trap in forensic evaluations. 
For example, we encountered an issue where a raw `dd` image was disguised with an `.e01` extension. The AI's `ewfmount` tool failed because it couldn't locate the expected container paths. If an LLM hits an error like this, it usually gets stuck in a hallucination loop. 

To solve this, we engineered a **Dynamic Fallback Mount Mechanism**. If `ewfmount` fails or the `ewf1` stream isn't generated, our backend intercepts the error, gracefully fails-open, assumes it is a raw image, and autonomously attempts a direct raw loopback mount. This self-correction allowed the AI to recover from the error without human intervention.

## 🏆 Accomplishments that we're proud of
We are incredibly proud of the **Multi-Source Correlation Engine**. Typically, analyzing memory and disk images requires separate analysts working in silos. DigiSec's ability to unify these artifacts into a single timeline—flagging a process that exists in memory but has no corresponding Prefetch or MFT record on disk—is a massive leap forward for automated triage. We are equally proud of achieving this while maintaining $100\%$ zero-spoliation compliance.

## 📚 What we learned
We learned the immense power of the **Model Context Protocol (MCP)**. By defining strict tool boundaries, we realized you don't have to choose between AI autonomy and system security. We also deepened our understanding of FUSE file systems, EnCase container structures, and how to programmatically manage complex forensic dependencies in sandboxed environments.

## 🚀 What's next for DigiSec
The next evolution of DigiSec involves integrating **Cloud Forensics**. We plan to add native MCP tools to ingest AWS CloudTrail logs and Azure Active Directory sign-ins, allowing the autonomous agent to correlate an on-premise endpoint compromise directly to cloud infrastructure lateral movement.
