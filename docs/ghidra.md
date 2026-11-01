# Ghidra Headless Integration

## Overview

Xaynx Reverse Lab features an optional, fully decoupled integration with the NSA Ghidra software reverse engineering suite. Ghidra is **never a mandatory dependency**; the core desktop application, disassembly engine, and file analyses operate independently.

## Integration Architecture

When requested by the user, Xaynx Reverse Lab invokes Ghidra's official headless batch analyzer:

```
<ghidra_install>/support/analyzeHeadless <temp_project_dir> xrl_project \
    -import <target_file> \
    -scriptPath <ghidra_scripts_dir> \
    -postScript XrlExport.java <output.json> <decompile: 0|1> <max_functions> \
    -analysisTimeoutPerFile <timeout_seconds> \
    -deleteProject
```

### Script: `ghidra_scripts/XrlExport.java`

`XrlExport.java` runs directly within Ghidra's JVM environment. It queries Ghidra's `FunctionManager` to collect:
- Function entry addresses and body byte lengths.
- Function signatures and calling conventions.
- Flags indicating whether functions are external or compiler thunks.
- Optional C pseudocode produced by Ghidra's decompiler engine (`DecompInterface`).

The results are written to an intermediate JSON file. Once the process terminates, Xaynx Reverse Lab parses this JSON and displays the functions and decompilation in the UI.

## Configuring Ghidra

1. Download and extract Ghidra (version 10.x or 11.x) from [ghidra-sre.org](https://ghidra-sre.org/).
2. Ensure a compatible Java Development Kit (JDK 17 or JDK 21) is installed and available in your environment path or `JAVA_HOME`.
3. In **Xaynx Reverse Lab**, navigate to **Settings > Ghidra Integration**:
   - Click **Detect** to search standard installation directories (e.g. `GHIDRA_INSTALL_DIR`, `/Applications`, Homebrew, `C:\Program Files`, `C:\tools`).
   - Or click **Browse...** to select the directory containing `ghidraRun` and `support/analyzeHeadless`.
4. Open a binary file and navigate to **Disassembly > Ghidra (optional)**.
5. Check **Also run Ghidra's decompiler** if C pseudocode is desired, then click **Run Ghidra analysis**.

