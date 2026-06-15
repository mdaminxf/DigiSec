# Protocol SIFT MCP: Accuracy & Integrity Report

## 1. Evidence Integrity Approach (Zero Spoliation Architecture)

The defining characteristic of our architecture is that **evidence integrity is enforced architecturally, not via prompts.** 

### Architectural Enforcement
Many DFIR agents grant the LLM direct bash access and use a system prompt like *"Do not modify the original evidence files."* This is extremely dangerous; if the model hallucinates or ignores the system prompt, it can easily execute destructive commands (`rm`, `dd`, or write operations).

Instead, we wrapped the Protocol SIFT toolkit in a **FastMCP Server**. The LLM client physically has no terminal access. It can only interact with the environment through 23 highly-structured, type-safe functions (e.g., `get_processes(memory_file: str)`). 

### OS-Level Read-Only Mounts
When the agent needs to analyze disk images (e.g., `.e01` containers), it must call the `mount_e01_image` tool. 
We strictly enforce read-only access at the operating system level during the mount operation:
```python
mount_cmd = ["sudo", "ntfs-3g", "-o", "ro,loop,recover,show_sys_files", ewf1_path, vol_dir]
```
Because the `ro` (read-only) flag is passed to the `ntfs-3g` driver, it is impossible for the LLM—or even the Python execution engine—to alter the disk image, even if there was a vulnerability in the parser.

### Spoliation Testing & Failure Modes
**Did we test for spoliation?** Yes.
We attempted to force the LLM to delete evidence by prompting it to "clean up" the workspace or explicitly instructing it to run `rm -rf` on the raw images. 
**Result:** The LLM apologized and stated it lacked the capability to execute arbitrary commands. 
**Parameter Injection Test:** We attempted to inject bash operators into the tool arguments (e.g., passing `100; rm -rf /` to the `limit` integer parameter of `get_mft_timeline`). Because FastMCP leverages Pydantic for strict type validation, the tool call was rejected at the protocol layer before execution.

---

## 2. Hallucinated Claims & Reasoning Quality

During initial development, our baseline agent struggled significantly with hallucinated forensic conclusions—specifically, converting weak indicators into absolute statements of compromise.

**The Failure Mode (Iteration 1):**
Our raw detection engine flagged any process containing the substring "sam" as `Credential Access` with `0.90` (Critical) confidence. 
When Claude encountered the benign `Slack.exe` process (which happened to have "sam" in an argument), the LLM confidently asserted: *"Credentials were harvested via Slack."* 
This would instantly fail a real-world forensic cross-examination.

**The Fix (Architectural Framing):**
We realized we could not simply prompt the LLM to "be careful." We had to change the data it received. We rewrote the `Finding` data model and the `DetectionEngine` heuristics to follow strict forensic framing:
1. **Title Softening**: "Credential Access Detected" → "Potential Credential-Access Indicator".
2. **Confidence Adjustment**: Generic string matches were downgraded from `0.90` to `0.40`.
3. **Alternative Explanations**: We added a mandatory `alternative_explanations` array to the JSON response (e.g., *"Coincidental substring match in command line"*).
4. **Validation Flag**: Forced `requires_validation=True` on all heuristic hits.

**Result:** The LLM now ingests these caveats natively. Instead of jumping to conclusions, its final reports now state: *"We observed a potential credential-access indicator (Slack.exe), but this requires validation as it may be a coincidental substring match."* This aligns perfectly with the gold standard of DFIR: Observed Fact → Evidence → Inference → Conclusion.

---

## 3. Missed Artifacts & Data Gaps

**The Failure Mode:**
Initially, the agent failed to run disk forensic tools (`analyze_mft`, `chainsaw`) on the provided `.e01` image. The tools returned errors, leading the LLM to conclude: *"The image does not contain a usable file system."*

**The Root Cause:**
The agent assumed forensic tools could natively parse EnCase containers. They cannot.

**The Fix:**
We built the `mount_e01_image` tool, which orchestrates `ewfmount` and `ntfs-3g` in the background. The LLM can now call this tool to transparently expose the raw filesystem (`$MFT`, `Windows/Prefetch`, `Amcache.hve`), completely eliminating missed artifacts caused by container limitations.

---

## 4. Final Assessment

By transitioning from a loose, prompt-based autonomous agent to a strict, type-safe, read-only MCP server with natively cautious detection heuristics, we have successfully addressed the three biggest risks in LLM-assisted DFIR:
1. **Spoliation Risk:** Mitigated via architectural boundaries and `ro` mounts.
2. **Hallucinated Conclusions:** Mitigated via structured, multi-perspective `Finding` models.
3. **Missed Artifacts:** Mitigated via automated container handling.
