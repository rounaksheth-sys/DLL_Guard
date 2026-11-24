 # DLLGuard

A lightweight Windows endpoint auditing tool that inspects DLLs loaded by running processes, evaluates their file paths and Authenticode digital signatures, and assigns a heuristic risk score to help spot potential DLL hijacking or untrusted module loads.

> **Disclaimer:** A `HIGH` or `MEDIUM` score means a DLL matched one or more heuristic rules—it is **not** proof of malware. Many legitimate applications (such as browsers, Electron apps, and game utilities) store unsigned or third-party DLLs inside user-writable directories like `AppData` or `ProgramData`.

---

## Features

* **Process & Module Inspection:** Enumerates loaded `.dll` and `.drv` modules across all running processes, a specific executable name, or a single PID.
* **Batched Authenticode Verification:** Verifies digital signatures and certificate publishers (`CN`) in batches of 50 files via PowerShell to minimize subprocess overhead, with in-memory caching for repeated modules.
* **Heuristic Risk Scoring:** Evaluates each loaded DLL based on directory permissions, application folder isolation, signature validity, and publisher mismatch against the host `.exe`.
* **Interactive CLI & Deduplication:** Groups shared DLLs across multiple processes to reduce alert noise, with options to filter by risk level, sort results, or include trusted Windows/Program Files modules.
* **CSV Report Export:** Exports filtered or complete scan results to UTF-8 CSV files for further analysis.
* **DLL Hijack Simulation Harness:** Includes a C-based test executable and sample DLL in `Demo/` to safely demonstrate and verify detection behavior.

---

## Project Structure

```text
dllguard/
├── src/
│   └── dllguard.py          # Main scanner and interactive CLI
├── Demo/
│   ├── testapp.c            # Sample host application for testing DLL loads
│   └── harmless.c           # Sample unsigned DLL payload for demo purposes
├── Docs/                    # Screenshots and project documentation
├── requirements.txt         # Python dependencies
└── README.md
```
