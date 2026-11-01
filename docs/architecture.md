# System Architecture

**Xaynx Reverse Lab** is organized into modular layers with a strict separation between binary parsing, static analysis, disassembly, report generation, and desktop presentation.

```
                    +------------------------------------+
                    |       Desktop GUI (Qt 6)           |
                    | (HexView, EntropyHeatmap, StringsTable, CfgGraphView, XrefGraphView, Workspace) |
                    +-----------------+------------------+
                                      |
                                      v
  +-----------------------------------+-----------------------------------+
  |                        Core Library (xrl_core)                        |
  |                                                                       |
  |  +--------------------+   +-------------------+   +----------------+  |
  |  |  Format Parsers    |   |  Static Analyzer  |   | Disassembler   |  |
  |  |  (PE, ELF, Mach-O) |   |  & Heuristics     |   | (Capstone)     |  |
  |  +--------------------+   +-------------------+   +----------------+  |
  |                                                                       |
  |  +--------------------+   +-------------------+   +----------------+  |
  |  |  Reporting Engine  |   |  ByteReader /     |   | Ghidra Glue    |  |
  |  |  (JSON & Text)     |   |  Safe Math        |   | (analyze-      |  |
  |  |                    |   |                   |   |  Headless)     |  |
  |  +--------------------+   +-------------------+   +----------------+  |
  |                                                                       |
  |  +--------------------+   +----------------------------------------+  |
  |  | XREF Engine       |   | CFG-backed references, call graph,      |  |
  |  |                   |   | symbol/data/string indexes & exporters  |  |
  |  +--------------------+   +----------------------------------------+  |
  |  | Workspace Store  |   | Versioned JSON, validation, integrity    |  |
  |  |                   |   | checksum, atomic local persistence       |  |
  |  +--------------------+   +----------------------------------------+  |
  |  |  Sha256 Engine     |   | RFC 8259 Json Parser / Serializer     |  |
  |  +--------------------+   +----------------------------------------+  |
  +-----------------------------------+-----------------------------------+
                                      ^
                                      |
                    +-----------------+------------------+
                    |             xrl-cli                |
                    |      (Headless CLI front-end)      |
                    +------------------------------------+
```

## Module Directory Structure

```
.
|-- CMakeLists.txt                # Root CMake project
|-- include/                      # Public C++20 API
|   |-- xrl/
|       |-- cfg.hpp               # Reachable CFG model, analysis options, and JSON/DOT exports
|       |-- xref.hpp              # Unified references, XREF index, call metrics, and JSON/CSV/DOT exports
|       |-- analyzer.hpp          # File loading, limits, top-level analysis entry point
|       |-- entropy.hpp           # Streamed file entropy analysis and report export
|       |-- strings.hpp           # Streamed multi-encoding string extraction and classifications
|       |-- static_analysis.hpp  # Evidence, correlations, scoring methodology, and report API
|       |-- workspace.hpp        # Persistent investigation projects and local workspace storage
|       |-- byte_reader.hpp       # Safe bounds-checked endianness reader
|       |-- disassembler.hpp      # Capstone wrapper and start-point discovery
|       |-- formats.hpp           # Format-specific parser declarations
|       |-- ghidra.hpp            # Optional Ghidra headless integration
|       |-- json.hpp              # Minimal strictly-validated JSON parser/serializer
|       |-- report.hpp            # JSON & Plain-text report generators
|       |-- sha256.hpp            # Self-contained FIPS 180-4 SHA-256 implementation
|       |-- types.hpp             # Shared domain data models
|       `-- util.hpp              # Math, entropy, string sanitization, time helpers
|-- src/
|   |-- analysis/
|   |   |-- cfg.cpp               # Capstone-backed CFG recovery and graph metrics
|   |   |-- xref.cpp              # CFG-backed reference indexing, metrics, and bounded export
|   |   |-- static_analysis.cpp   # Evidence-based rules, correlations, JSON and HTML reports
|   |   |-- workspace.cpp         # Versioned workspace JSON, validation, integrity and atomic writes
|   |   |-- analyzer.cpp          # Buffer/file loading pipeline and section finalizer
|   |   |-- entropy.cpp           # Buffered block entropy, SHA-256, JSON and CSV
|   |   |-- strings.cpp           # Buffered ASCII/UTF string extraction and transparent classifiers
|   |   `-- heuristics.cpp        # Unverified static observations (entropy, RWX)
|   |-- cli/
|   |   `-- main.cpp              # Headless CLI entry point
|   |-- core/
|   |   |-- json.cpp              # JSON implementation
|   |   |-- sha256.cpp            # SHA-256 implementation
|   |   `-- util.cpp              # Utility implementation
|   |-- disassembly/
|   |   `-- disassembler.cpp      # Capstone disassembly routines
|   |-- formats/
|   |   |-- detect.cpp            # Magic byte container detection
|   |   |-- elf.cpp               # ELF 32/64 little/big-endian parser
|   |   |-- macho.cpp             # Mach-O 32/64 thin & fat universal binary parser
|   |   `-- pe.cpp                # PE32 / PE32+ (COFF/Optional/DataDirs) parser
|   |-- ghidra/
|   |   `-- ghidra.cpp            # Process invocation and JSON output ingestion
|   |-- reporting/
|   |   `-- report.cpp            # Schema v1.0 JSON & human text formatters
|   `-- ui/
|       |-- CMakeLists.txt        # Qt 6 UI targets & resource packaging
|       |-- CfgGraphView.cpp/.hpp # Interactive block graph and branch-edge visualization
|       |-- XrefGraphView.cpp/.hpp # Bounded interactive XREF relationship graph
|       |-- GhidraRunner.cpp/.hpp # Asynchronous headless worker process manager
|       |-- HexView.cpp/.hpp      # Custom painted 64-bit scrollable hex viewer
|       |-- EntropyHeatmap.cpp/.hpp # Zoomable, selectable block entropy grid
|       |-- StringsTable.cpp/.hpp # Searchable, sortable, filterable string results
|       |-- WorkspaceWidget.cpp/.hpp # Project, file, history, note, bookmark, tag and backup UI
|       |-- MainWindow.cpp/.hpp   # Application window and tabbed workflow
|       |-- TableWidgets.hpp      # Fast string-table models and filtered tables
|       |-- Theme.cpp/.hpp        # Fusion-based charcoal dark theme
|       |-- UiUtil.hpp            # Unicode path translation and format conversions
|       `-- main.cpp              # Desktop application main()
|-- ghidra_scripts/
|   `-- XrlExport.java            # Headless Ghidra script extracting functions/decompile
|-- tests/
|   |-- CMakeLists.txt            # Test configuration with GoogleTest
|   |-- test_cfg.cpp              # CFG recovery, metrics, bounds, and export tests
|   |-- test_xref.cpp             # Reference extraction, call metrics, limits, and export tests
|   |-- test_static_analysis.cpp # Rule evidence, correlations, ranges, scoring, and reports
|   |-- fixtures.hpp              # Synthetic PE, ELF, Mach-O binary generators
|   |-- test_analyzer.cpp         # In-memory and file pipeline tests
|   |-- test_disassembly.cpp      # Capstone decoder tests
|   |-- test_formats.cpp          # Format parsing, malformed & truncation tests
|   |-- test_ghidra.cpp           # Headless command validation and parser tests
|   |-- test_json.cpp             # RFC 8259 parser/serializer tests
|   |-- test_report.cpp           # Report schema tests
|   |-- test_util.cpp             # SHA-256 FIPS vectors, entropy, bounds tests
|   |-- test_entropy.cpp      # Streamed entropy statistics, edge cases and exports
|   `-- test_strings.cpp      # Multi-encoding extraction, bounds and classifications
`-- docs/
    |-- analysis-notes.md         # Heuristic limits and safety principles
    |-- architecture.md           # This document
    |-- ghidra.md                 # Headless Ghidra setup and execution model
    `-- packaging.md              # Distribution, bundling and installer instructions
```

## Relocations and Function Explorer

The shared `BinaryInfo` model carries parser-derived relocation records with their address, optional file mapping, relocation type, optional symbol/addend/target, and evidence source. The PE parser reads COFF section and image-base relocation records and CodeView RSDS identity metadata; ELF reads REL/RELA records, GNU build ID/debuglink, and DWARF section presence; Mach-O reads section relocation records and retains the load-command UUID. Parser bounds are enforced before records are accepted. Unknown targets and unmapped offsets remain optional rather than being synthesized.

The Function Explorer reuses `discoverFunctionCandidates` and the existing parser output. It displays entry-point, export, function-symbol, and executable-section-start evidence, and adds call metrics only from an XREF result whose SHA-256 matches the current file. Actions navigate to the existing CFG, disassembly, and Hex Viewer. Relocation/debug identifier tables are metadata views, not independent analysis engines. PDB/dSYM/debug files are not searched for or loaded, and DWARF is not fully decoded; section starts and entry points do not prove function boundaries.

## Persistent Analysis Workspace

The Workspace page is a local metadata layer over the existing file-analysis workflows. Its `WorkspaceData` model contains projects, file references, analysis and comparison snapshots, notes, bookmarks, tags, and session selection. Source binaries remain at their original paths; the workspace does not copy or execute them.

`src/analysis/workspace.cpp` serializes this model using the existing RFC 8259 JSON implementation. Schema v2 includes a SHA-256 integrity checksum over the serialized workspace body; loading validates the checksum, object structure, reference limits, and embedded report JSON before accepting data. Schema v1 is migrated in memory. Writes validate the candidate first, write a sibling temporary file, and atomically replace the destination (using `MoveFileExW` with write-through semantics on Windows and filesystem rename on POSIX). Per-report and whole-workspace size limits bound retained metadata. Unix-like workspace directories are restricted to owner access.

`MainWindow` owns persistence at the platform `AppDataLocation` under `workspace/workspace.json`. The UI persists edits through a candidate-copy/commit callback so a failed write does not replace the in-memory state. The startup path restores the last selected project/file and active page; file identity is checked against SHA-256 before stale paths can be treated as the same binary. A changed hash requires confirmation, and old report/note/bookmark data remains tied to its recorded hash. Backup and restore use the same validated JSON format; restore imports projects with new IDs instead of overwriting local projects, and never packages source binaries. The integrity checksum detects accidental corruption but does not authenticate a backup's author.

Analysis reports are captured when an analyzed file is already referenced by the active project and the serialized report fits the per-record limit. CFG/XREF and other transient in-memory view state is not persisted; users can rerun those engines after restoring a project.

## Security & Untrusted Input Model

1. **No Target Execution**: Executable-format parsing reads files as data into memory; entropy and string analysis use buffered streams. The application never loads target libraries, executes target entry points, or executes foreign plugins.
2. **Bounds-Checked Parsing**: All offset arithmetic uses `xrl::Reader`, which validates `offset + length <= buffer_size` without unsigned integer wrap-around.
3. **Explicit Limits**: Executable parsing is configured through `xrl::Limits`, enforcing caps on in-memory file size (default 512 MiB), section counts (4096), load commands (16384), DLL imports (4096), and symbols (200,000). Entropy analysis streams independently and retains one result per analyzed block. String extraction also caps results and retained string text.
4. **Bounds-Checked String Ranges**: String offsets and byte lengths are validated against the initial file size; extraction uses fixed-size read buffers and does not execute the analyzed file.
5. **Sanitized Character Encodings**: Binary strings from symbol tables and headers are sanitized against control characters and invalid UTF-8 codepoints prior to JSON serialization or display.
6. **Explainable Static Analysis**: Rules consume existing parsed metadata, the validated file snapshot, Strings Explorer, Entropy Heatmap, and optional prior CFG results. Evidence ranges are checked before inclusion. String and entropy results read from disk are accepted only when their SHA-256 matches the loaded parser result. Finding and string-evidence counts are capped; correlations never inflate the transparent, deduplicated evidence-prioritization score. The score is not a probability or verdict.
7. **Workspace Integrity**: Local workspace JSON is size-limited, parsed and validated before load/write, and protected against accidental corruption by a checksum. The checksum is not a digital signature; backups should be protected as local investigation metadata.

## Explainable Static Analysis

The Qt page runs `xrl::analyzeStatic` in a cancellable background task and displays findings, supporting evidence, confidence, evidence quality, benign explanations, and next steps. It can route findings to existing views and export JSON or escaped HTML. The engine aggregates results from the existing PE/ELF/Mach-O parser, Strings Explorer, Entropy Heatmap, and optionally a CFG generated earlier by the CFG page; it does not add a competing parser or extraction implementation.

Current rules cover section range/permission/size anomalies, entry-point mapping, selected imported API capability groups, deterministic string categories and command-line-like fragments, fixed 7.2 bits/byte entropy indicators, and selected metrics from a supplied CFG. Three correlation families join independent observations without increasing the score. Severity weights are 0/8/18/32/45 (informational through critical); candidate points multiply severity by confidence and evidence-quality percentages. Only the strongest finding per evidence group is counted; the rounded score is capped at 100 and marked inconclusive with fewer than two independent positive-weight groups. It is a review-priority aid, never malware probability.

Limitations: CFG evidence is absent unless the user has already analyzed a function; the static page does not automatically traverse all functions. Relocation records and debug identifiers are exposed through the shared parser model and UI/reporting, but are not evidence inputs to current static-analysis rules. The engine caps output at 600 findings and 250 retained string examples per category. Incomplete parser data is reported as a warning and partial parsing diagnostic rather than treated as confirmed absence.
