# Static Analysis

CodeQL-based static analysis tools for vulnerability detection and interprocedural control flow graph (ICFG) extraction.

## Files

- **`static_analysis.py`** — ScubaTrace-based static analysis runner. Converts source files to UTF-8 encoding and runs taint/control flow analysis on vulnerability repositories.

## ICFG (`CodeQL/`)

Automated pipeline for extracting Interprocedural Control Flow Graphs from CVE repositories:

- **`batch_runner.py`** — Batch processor that iterates over all CVE directories, auto-detects language, creates CodeQL databases, and extracts ICFGs with timeout handling and resume support.
- **`codeql_auto_analyzer.py`** — Core analyzer that detects the programming language of a project, creates a CodeQL database, and runs ICFG queries.
- **`queries/`** — CodeQL ICFG query packs for C, C++, Go, Java, JavaScript, Python, and Ruby.

## CodeQL Callgraph Example (`codeql-callgraph-example/`)

Example project demonstrating CodeQL call graph extraction on a sample C application. Includes sample source, CodeQL queries, build scripts, and visualization tools.

## Zoneminder Callgraph (`zoneminder-callgraph/`)

Real-world CodeQL call graph analysis of the ZoneMinder project, with extracted call graphs, CFGs, PDGs, and cross-file call analysis.

## Subdirectories

- **`tools/`** — Downloaded CodeQL CLI distribution. Excluded from version control.
- **`Results/CodeQL/`** — Generated ICFG outputs. Excluded from version control.
