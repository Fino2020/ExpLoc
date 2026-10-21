# ExpLoc — Vulnerability Issue Localization & Explanation Generation

Two-step vulnerability localization with exploit chain explanation: given a vulnerability issue report, Step 1 iteratively discovers vulnerable files and pinpoints functions; Step 2 traces exploit chains through code search and call graph analysis.

## Project Architecture

```
ExpLoc/
├── Dataset/                          # CVE dataset + ground truth
│   ├── dataset_with_changed_files_filter.json   # Main dataset (746 CVEs)
│   ├── GT_Function/                  # Function-level ground truth
│   └── GT_Chains_V3/                 # Exploit chain ground truth (VTP evaluation)
├── Localization/                     # Our method
│   ├── pipeline.py                   # Pipeline orchestrator (v2 iterative two-stage by default)
│   ├── evaluate.py                   # Evaluation (file/function/module Acc@k)
│   ├── step1_v2/                     # Step 1: IterativeFileHunter + FuncPinpointer
│   ├── step2_explainer/              # Step 2: Exploit Chain Tracing
│   ├── shared/                       # Config, ICFG loader, GT loader, sink_db
│   ├── step1_locator/                # Retriever, ranker, issue linker, memory store
│   └── acr_baseline/                 # SearchBackend (O(1) code index) + ModelClient
├── Static_Analysis/                  # ICFG construction (CodeQL + ScubaTrace/Joern)
│   ├── CodeQL/                       # CodeQL-based ICFG extraction
│   │   ├── codeql_auto_analyzer.py   # Auto-detect language, create DB, run queries
│   │   ├── batch_runner.py           # Batch runner across CVEs
│   │   └── queries/                  # .ql query files (7 languages)
│   └── ScubaTrace/                   # Joern/ScubaTrace CPG → ICFG conversion
│       ├── generate_cpg.py           # Generate Code Property Graph via Joern
│       ├── generate_cpg_batch.py     # Batch CPG generation
│       └── cpg_to_icfg.py            # Convert CPG to ICFG CSV
├── KG_Construction/                  # Issue Resolution Knowledge Graph builder
│   ├── Build_KG_GraphML.py           # Build per-repo Issue→Commit→File→Function GraphML KGs
│   ├── Build_knowledge_graph.py      # Knowledge graph construction pipeline
│   ├── data_collection.py            # NVD/OSV/GitHub data collection (OAuth2, token rotation)
│   └── issue_history_generation.py   # Issue history JSON generation
└── Results/
    └── Localization_Step2_V16_Full/  # 682 CVE results (Step1 + Step2)
```

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.12+. Configure `.env` at project root:

```
REPO_BASE=/path/to/cloned/repos
OPENAI_DEFAULT_KEY=sk-...
OPENAI_BASE_URL=https://your-proxy/v1/
OPENAI_MODEL=deepseek-v4-flash
```

## Data Preparation

The pipeline requires three categories of pre-computed data:

### 1. Clone Git Repositories

```bash
# Structure: $REPO_BASE/{CVE-ID}/{Owner}/{Project}
# Example: /data/repos/CVE-2013-7449/hexchat/hexchat
```

### 2. Build ICFG (Static Analysis)

```bash
cd Static_Analysis/

# Option A: CodeQL (7 languages: C/C++, Python, JS/TS, Java, Go, Ruby, PHP)
python3 CodeQL/batch_runner.py --limit 0 --workers 8
# Output: Results/CodeQL/{CVE-ID}/icfg_icfg_db.csv

# Option B: ScubaTrace/Joern (CPG-based)
python3 ScubaTrace/generate_cpg_batch.py --limit 0 --workers 8
# Output: Results/ScubaTrace/{CVE-ID}/icfg_scubatrace.csv
```

### 3. Build IR-KG (Issue Resolution Knowledge Graph)

```bash
cd KG_Construction/

# Step 1: Collect issue/commit/PR metadata from NVD/OSV/GitHub
python3 data_collection.py

# Step 2: Generate issue history JSON per repo
python3 issue_history_generation.py

# Step 3: Build GraphML knowledge graphs
python3 Build_KG_GraphML.py
# Output: Graphs/{owner}_{project}.graphml, history/history/{owner}_{project}.json
```


## Running the Pipeline

### Quick Start (single CVE)

```bash
cd Localization/
python3 pipeline.py --cves CVE-2015-1862
```

### Batch Mode (all 746 CVEs)

```bash
cd Localization/
python3 pipeline.py --limit 0 --workers 8 --resume
```

`--resume` skips CVEs that already have a `result.json`, so interrupted runs can safely restart.

### Full Command Reference

```bash
python3 pipeline.py [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--limit N` | `10` | Max CVEs to process (`0` = all) |
| `--skip N` | `0` | Skip first N CVEs in manifest |
| `--cves ID1,ID2` | — | Comma-separated CVE list (overrides `--limit`/`--skip`) |
| `--output DIR` | `Results/Localization/Localization` | Output directory for result JSONs |
| `--manifest PATH` | `Dataset/dataset_with_changed_files_filter.json` | Dataset manifest path |
| `--workers N` | `1` | Parallel workers (recommend 4–8) |
| `--resume` | off | Skip CVEs with existing `result.json` |

### Ablation Variants

| Flag | Effect |
|------|--------|
| `--no-kg` | Remove Issue Resolution KG (RQ3a: w/o IR-KG) |
| `--no-step1-v2` | Use legacy HybridAgent instead of iterative two-stage (w/o Agent) |
| `--no-step1-v2 --no-kg` | Remove both Agent and IR-KG (RQ3a: w/o both) |
| `--no-step2` | Step 1 only (localization without explanation) |

### Step 2 Mode

| Flag | Description |
|------|-------------|
| `--step2-mode call_site_windows` | **(default)** ICFG call-site context windows + LLM slot classification |
| `--step2-mode greedy` | ICFG PathTracer forward trace with adaptive termination |


### Evaluation

```bash
cd Localization/
python3 evaluate.py --results ../Results/Localization_Step2_V16_Full
```

Three granularities, strict top-k accuracy (ref: LocAgent R-Precision):

| Level | Metric | Definition |
|-----------|------------|------------|
| File | Acc@1, Acc@3, Acc@5 (strict) | ALL GT files in top-k predictions |
| Function | Acc@5, Acc@10 (strict) | ALL GT functions in top-k predictions |
| Module | Acc@5, Acc@10 (relaxed) | ANY GT function in top-k (within patched class) |

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
