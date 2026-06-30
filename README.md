# ExpLoc — Vulnerability Localization & Explanation

Two-stage vulnerability localization with exploit chain explanation: given a CVE report, Stage 1 iteratively discovers vulnerable files and pinpoints functions; Stage 2 traces exploit chains through code search and call graph analysis.

## Project Architecture

```
ExpLoc/
├── Dataset/                          # CVE dataset + ground truth
│   ├── dataset_with_changed_files_filter.json   # Main dataset (746 CVEs)
│   ├── GT_Function/                  # Function-level ground truth
│   └── GT_Chains_V3/                 # Exploit chain ground truth (VTP evaluation)
├── Localization/                     # Our method
│   ├── pipeline.py                   # Pipeline orchestrator
│   ├── evaluate.py                   # Evaluation (file/function/module Acc@k)
│   ├── step1_v2/                     # Stage 1: IterativeFileHunter + FuncPinpointer
│   ├── step2_explainer/              # Stage 2: Exploit Chain Tracing
│   ├── shared/                       # Config, ICFG loader, GT loader, sink_db
│   ├── step1_locator/                # Retriever, ranker, issue linker, memory store
│   └── acr_baseline/                 # SearchBackend (O(1) code index) + ModelClient
└── Results/
    └── Localization_Step2_V16_Full/  # 682 CVE results (Step1 + Step2)
```

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.12+. Configure `.env` in `Localization/`:

```
REPO_BASE=/path/to/cloned/repos
OPENAI_DEFAULT_KEY=sk-...
OPENAI_BASE_URL=https://your-proxy/v1/
OPENAI_MODEL=deepseek-v4-flash
```

---

## Our Method

### Stage 1: Iterative File Hunter + Function Pinpointer

**Stage 1a — IterativeFileHunter** (multi-round LLM agent for file discovery)

Uses ACR's SearchBackend (class/function/text O(1) index) with 8 search APIs. LLM agent runs up to 5 rounds, calling 3-5 APIs per round, following a BROAD → TARGETED → DEEP DIVE → EXPAND strategy:

| API | Purpose |
|-----|---------|
| `search_code` / `search_code_in_file` | Search code strings across codebase or file |
| `search_method` / `search_method_in_file` / `search_method_in_class` | Search function/method by name |
| `search_class` / `search_class_in_file` | Search class by name |
| `get_code_around_line` | Read code context around a line |

- Fallback: if <3 files found, retry without static evidence for wider search
- Output: `vulnerable_files[]` with scores and reasons

**Stage 1b — FuncPinpointer** (single-pass LLM for function refinement)

Takes top-10 files from Stage 1a, extracts full function bodies via tree-sitter, annotates with CodeQL static analysis alerts, and calls LLM in single-pass mode to identify specific vulnerable functions.

- Scoring: CodeQL-matched functions (0.80-1.00) > commit-patch functions (0.55-0.79) > structural relations (0.30-0.54)
- Fallback: if <3 functions, keep Stage 1a functions
- Output: refined `vulnerable_functions[]`

### Stage 2: Exploit Chain Tracing

Two-phase agent that traces complete vulnerability exploit chains:

**Phase 1 — Keyword Extraction** (1 LLM call, no tools): Extracts `suspicious_functions`, `suspicious_files`, `search_terms`, `vulnerability_type`, `cwe_keywords` from the CVE report.

**Phase 2 — Exploit Chain Tracing** (3 rounds, 8 tools): Agent calls code search and call graph tools to trace Source → Propagation → MissingValidation → Sink:

| Tool | Source | Purpose |
|------|--------|---------|
| `search_code` / `search_method` / `search_class` | SearchBackend | Full codebase O(1) search |
| `read_file` / `get_code_around` | SearchBackend | Read source context |
| `pinpoint_line` | Repo files | Verify specific code lines exist |
| `get_callees` / `get_callers` | ICFG | Downstream/upstream call tracing |
| `find_path` | ICFG | Connect source → sink through call graph |

Strategy: Extract APIs → Search code → Read files → `get_callees` downstream → `get_callers` upstream → `find_path` → `pinpoint_line` verify each edge.

Output: `exploit_chains[]` with verified edges (file, line, code), filled archetype slots, and NL summary.

### Key Design Decisions

- **Anti-leakage**: `before_date` filter on all commit searches; Issue linker uses only history JSON + git log
- **LLM fallback chain**: `OPENAI_DEFAULT_KEY` → `OPENAI_DS_API_KEY` → `DEEPSEEK_API_KEY`
- **IterativeFileHunter**: SearchBackend for DISCOVERY (O(1)), ICFG for VERIFICATION
- **Exploit Chain**: Every edge must have `pinpoint_line`-verified line numbers

---

## Evaluation

Three granularities, strict top-k accuracy (ref: LocAgent R-Precision):

| Level | Metric | Definition |
|-------|--------|------------|
| File | Acc@1, Acc@3, Acc@5 (strict) | ALL GT files in top-k predictions |
| Function | Acc@5, Acc@10 (strict) | ALL GT functions in top-k predictions |
| Module | Acc@5, Acc@10 (relaxed) | ANY GT function in top-k (within patched class) |

```bash
cd Localization/
python3 evaluate.py --results ../Results/Localization_Step2_V16_Full
```

### Results on Main Dataset (682 CVEs)

| File Acc@5 (S) | Func Acc@10 (S) | Module Acc@10 (R) |
|:---:|:---:|:---:|
| 80.92% | 41.25% | 63.95% |

---

## Output Format

Each `result.json` in `Results/Localization_Step2_V16_Full/{CVE-ID}/`:

```json
{
  "cve_id": "CVE-XXXX-XXXXX",
  "vulnerable_files": [
    {"file": "path/to/file.c", "score": 0.95, "reason": "...", "evidence": {...}}
  ],
  "vulnerable_functions": [
    {"function": "func_name", "file": "path/to/file.c", "score": 0.88, "reason": "..."}
  ],
  "mode": "two_stage",
  "step2": {
    "step2_mode": "call_site_windows",
    "explanations": [{
      "function_rank": 1,
      "entry_function": "vuln_func",
      "entry_file": "src/file.c",
      "entry_line": 100,
      "filled_slots": {"Source": "...", "Sink": "..."},
      "path_chain": [{"from_func": "A", "to_func": "B", "slot": "Propagation"}],
      "statements": [{"file": "src/file.c", "line": 100, "code": "..."}],
      "code_snippets": [...],
      "nl_summary": "Input from main → parse without validation → strcpy overflow"
    }]
  }
}
```
