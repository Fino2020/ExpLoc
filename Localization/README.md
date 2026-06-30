# Localization — Two-Stage Vulnerability Localization & Exploit Chain Tracing

## Prerequisites

- Python 3.12+
- Git repos cloned at `$REPO_BASE/{CVE-ID}/{owner}/{project}`

```bash
pip install -r requirements.txt
```

## Configuration

Create `.env` at project root (`ExpLoc/.env`):

```bash
# Required
REPO_BASE=/mnt/e/Desktop/Localization_Repo/Localization_Repo
OPENAI_DEFAULT_KEY=sk-...
OPENAI_BASE_URL=https://your-proxy/v1/
OPENAI_MODEL=deepseek-v4-flash

# Optional fallback keys
OPENAI_DS_API_KEY=sk-...
DEEPSEEK_API_KEY=sk-...
```

## Quick Start

### 1. Run localization + explanation (single CVE)

```bash
cd Localization/

# Two-stage + iterative mode (our method)
python3 pipeline.py \
  --cves CVE-2013-7449 \
  --step1-v2 \
  --two-stage \
  --iterative
```

### 2. Run on multiple CVEs

```bash
# First 10 CVEs
python3 pipeline.py --limit 10 --step1-v2 --two-stage --iterative

# All CVEs, parallel
python3 pipeline.py --limit 0 --workers 8 --step1-v2 --two-stage --iterative

# Resume from CVE 50
python3 pipeline.py --skip 50 --limit 0 --workers 8 --step1-v2 --two-stage --iterative

# Specific CVEs
python3 pipeline.py --cves CVE-2015-1862,CVE-2016-1234 --step1-v2 --two-stage --iterative
```

### 3. Output

Results saved to `../Results/Localization/Localization/{CVE-ID}/result.json`:

```json
{
  "cve_id": "CVE-2013-7449",
  "vulnerable_files": [
    {"file": "src/common/server.c", "score": 0.95, "reason": "...", "evidence": {...}},
    {"file": "src/common/ssl.c", "score": 0.82, "reason": "..."}
  ],
  "vulnerable_functions": [
    {"function": "server_connect", "file": "src/common/server.c", "score": 0.88, "reason": "..."},
    {"function": "ssl_verify_callback", "file": "src/common/server.c", "score": 0.76, "reason": "..."}
  ],
  "mode": "two_stage",
  "step2": {
    "step2_mode": "call_site_windows",
    "explanations": [{
      "function_rank": 1,
      "entry_function": "server_connect",
      "entry_file": "src/common/server.c",
      "filled_slots": {"Source": "...", "Sink": "..."},
      "path_chain": [{"from_func": "A", "to_func": "B", "slot": "Propagation", "from_line": 100, "to_line": 120}],
      "statements": [{"file": "src/common/server.c", "line": 100, "code": "..."}],
      "nl_summary": "Input from main → parse without validation → strcpy overflow"
    }]
  }
}
```

## Evaluation

```bash
# Evaluate against ground truth
python3 evaluate.py --results ../Results/Localization_Step2_V16_Full

# Custom results directory
python3 evaluate.py --results ../Results/Localization/{CVE-ID}
```

Three granularity metrics:

| Level | Acc@k | Definition |
|-------|-------|------------|
| File | Acc@1, Acc@3, Acc@5 (strict) | ALL GT files in top-k predictions |
| Function | Acc@5, Acc@10 (strict) | ALL GT functions in top-k predictions |
| Module | Acc@5, Acc@10 (relaxed) | ANY GT function in top-k (within patched class) |

## Key Flags

| Flag | Description |
|------|-------------|
| `--step1-v2` | Use Stage 1 v2 pipeline (FileHunter + FuncPinpointer) |
| `--two-stage` | Enable two-stage mode (Stage 1 files → Stage 2 functions) |
| `--iterative` | Use IterativeFileHunter (multi-round agent) instead of single-pass |
| `--no-step2` | Skip exploit chain tracing (Step 1 only) |
| `--no-kg` | Ablation: no BM25 / issue history / commit knowledge |
| `--no-agent` | Heuristic-only mode (no LLM agent) |
| `--no-refine` | Skip function refinement pass |
| `--limit N` | Max CVEs (0 = all) |
| `--skip N` | Skip first N CVEs (resume) |
| `--cves A,B` | Specific CVE IDs (comma-separated) |
| `--workers N` | Parallel workers (default 1) |
| `--resume` | Skip CVEs with existing result.json |
| `--output PATH` | Custom output directory |

## Pre-built Results

682 CVE results available at `../Results/Localization_Step2_V16_Full/`. Generated with:

```bash
python3 pipeline.py --limit 0 --workers 8 --step1-v2 --two-stage --iterative
```
