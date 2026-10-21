# Localization — Two-Stage Vulnerability Localization & Exploit Chain Tracing

## Prerequisites

- Python 3.12+
- Git repos cloned at `$REPO_BASE/{CVE-ID}/{owner}/{project}`
- ICFG data (CodeQL or ScubaTrace CSVs) — see `../Static_Analysis/`
- (Optional) IR-KG data (issue history + GraphML) — see `../KG_Construction/`

```bash
pip install -r requirements.txt
```

## Configuration

Create `.env` at project root (`ExpLoc/.env`):

```bash
# Required
REPO_BASE=/path/to/cloned/repos
OPENAI_DEFAULT_KEY=sk-...
OPENAI_BASE_URL=https://your-proxy/v1/
OPENAI_MODEL=deepseek-v4-flash

# Optional fallback keys
OPENAI_DS_API_KEY=sk-...
DEEPSEEK_API_KEY=sk-...
```

### Data Dependencies

| Component | Required By | Build Command |
|-----------|------------|---------------|
| Git repos | Step 1 + Step 2 | Clone manually to `$REPO_BASE/{CVE-ID}/{Owner}/{Project}` |
| ICFG CSVs | Step 2 (call_site_windows, greedy) | `cd ../Static_Analysis && python3 CodeQL/batch_runner.py` |
| IR-KG (history + GraphML) | Step 1 legacy HybridAgent | `cd ../KG_Construction && python3 Build_KG_GraphML.py` |

Step 1 iterative mode uses SearchBackend directly and does NOT require pre-built IR-KG.

## Quick Start

### 1. Run localization + explanation (single CVE)

```bash
cd Localization/

# Default: two-stage + iterative + call_site_windows (our method)
python3 pipeline.py --cves CVE-2013-7449

# Skip Step 2 (localization only)
python3 pipeline.py --cves CVE-2013-7449 --no-step2
```

### 2. Run on multiple CVEs

```bash
# First 10 CVEs (default)
python3 pipeline.py

# All CVEs, parallel
python3 pipeline.py --limit 0 --workers 8

# Resume from CVE 50
python3 pipeline.py --skip 50 --limit 0 --workers 8 --resume

# Specific CVEs
python3 pipeline.py --cves CVE-2015-1862,CVE-2016-1234
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
| `--no-step1-v2` | Use legacy HybridAgent instead of iterative two-stage |
| `--no-two-stage` | Disable Stage 1b FuncPinpointer (file-level only) |
| `--no-iterative` | Use single-pass FileHunter instead of IterativeFileHunter |
| `--no-step2` | Skip exploit chain tracing (Stage 1 only) |
| `--step2-mode MODE` | Step 2 mode: `call_site_windows` (default), `greedy` |
| `--no-kg` | Ablation: no BM25 / issue history / commit knowledge |
| `--limit N` | Max CVEs (0 = all, default: 10) |
| `--skip N` | Skip first N CVEs (resume) |
| `--cves A,B` | Specific CVE IDs (comma-separated) |
| `--workers N` | Parallel workers (default 1) |
| `--resume` | Skip CVEs with existing result.json |
| `--output PATH` | Custom output directory |

## Ablation Examples

```bash
# No-KG ablation: skip RMS DB, use SearchBackend-only retriever
python3 pipeline.py --limit 10 --no-kg

# Legacy HybridAgent (no iterative, no two-stage)
python3 pipeline.py --limit 10 --no-step1-v2

# File-level only (no FuncPinpointer, no Step 2)
python3 pipeline.py --limit 10 --no-two-stage --no-step2

# Single-pass FileHunter (no iterative rounds)
python3 pipeline.py --limit 10 --no-iterative

# Greedy ICFG PathTracer instead of call_site_windows
python3 pipeline.py --limit 10 --step2-mode greedy
```

## Pre-built Results

682 CVE results available at `../Results/Localization_Step2_V16_Full/`. Generated with:

```bash
python3 pipeline.py --limit 0 --workers 8
```
