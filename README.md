# ExpLoc — Vulnerability Localization & Explanation

Experimental framework for CVE-based vulnerability localization (file/function/module ranking) and explanation (vulnerability-triggering path generation).

## Project Architecture

```
ExpLoc/
├── Dataset/                          # CVE dataset
│   ├── dataset_with_changed_files_filter.json   # Main dataset (746 CVEs)
│   ├── GT/                           # Ground truth (file/function labels, 753 CVEs)
│   └── GT_Chains/                    # Vulnerability-triggering path chains (763 CVEs)
├── Localization/                     # Our method: HybridAgent + ICFG explanation
│   ├── pipeline.py                   # Main pipeline orchestrator
│   ├── build_all_rms.py              # Build per-project RMS databases
│   ├── evaluate.py                   # Evaluation (file/function/module Acc@k, MRR, NDCG)
│   ├── shared/                       # Config, GT loader, ICFG loader, tree-sitter utils
│   ├── step1_locator/                # Step 1: LLM agent localization
│   ├── step2_explainer/              # Step 2: ICFG path tracing + NL explanation
│   └── locagent/                     # Graph-based agent adapter
├── Localization_baselines/           # All localization baselines
│   ├── HitMore/                      # MLP re-ranker (RandomForest + features)
│   ├── RepoMem/                      # Memory-augmented LLM agent
│   ├── VanillaLLM/                   # Pure LLM (no tools, no KG)
│   └── baseline_rlocator.py          # CodeBERT similarity ranking
├── Explanation_baselines/            # All explanation baselines
│   └── Explainable_Localization/     # GNN + MCTS + ICFG explanation pipeline
├── Static_Analysis/                  # Static analysis results (CodeQL, ScubaTrace)
├── KG_Construction/                  # Knowledge graph (GraphML issue graphs)
├── Results/                          # Output results per method
├── requirements.txt                  # Python dependencies
└── logic.md                          # Design philosophy & evaluation protocol
```

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.12+. Configure `.env` at project root:

```
REPO_BASE=/path/to/cloned/repos
MANIFEST_PATH=./Dataset/dataset_with_changed_files_filter.json
OPENAI_DEFAULT_KEY=sk-...
OPENAI_BASE_URL=https://your-proxy/v1/
OPENAI_MODEL=deepseek-v4-flash
```

Git repos expected at `$REPO_BASE/{owner}_{project}`.

---

## Our Method: Localization/

Two-step pipeline: (1) hybrid LLM agent locates vulnerable files/functions, (2) ICFG forward tracing generates explainable paths.

### Step 1: Vulnerability Localization

```bash
cd Localization/

# Build RMS databases (required before localization)
python3 build_all_rms.py                    # all CVEs
python3 build_all_rms.py --workers 8        # parallel
python3 build_all_rms.py --limit 10         # test first 10

# Run full pipeline (step 1 + step 2)
python3 pipeline.py --limit 10              # first 10 CVEs
python3 pipeline.py --cves CVE-2015-1862    # specific CVE
python3 pipeline.py --limit 0               # all CVEs
python3 pipeline.py --no-step2              # step 1 only
python3 pipeline.py --no-kg                 # ablation: no KG context
python3 pipeline.py --workers 4             # parallel

# Evaluate results
python3 evaluate.py --results ../Results/Localization
```

**Key parameters:**
| Flag | Description |
|------|-------------|
| `--limit N` | Max CVEs (0=all) |
| `--skip N` | Skip first N (resume) |
| `--cves A,B` | Specific CVE IDs |
| `--no-step2` | Skip explanation generation |
| `--no-kg` | Ablation: no BM25/issues/hotspots |
| `--workers N` | Parallel workers |
| `--resume` | Skip already-completed CVEs |

**Output:** `Results/Localization/{CVE-ID}/result.json`
```json
{
  "cve_id": "CVE-XXXX-XXXXX",
  "vulnerable_files": [{"file": "path/to/file.c", "score": 0.85, "reason": "..."}],
  "vulnerable_functions": [{"function": "func_name", "file": "...", "score": 0.80}],
  "confidence": "high",
  "step2": { "explanations": [...] }
}
```

### Evaluation Metrics

Three granularities, strict top-k accuracy:

| Level | Metric | Definition |
|-------|--------|------------|
| File | Acc@1, Acc@3, Acc@5 | Any GT file in top-k (relaxed) / All GT files in top-k (strict) |
| Function | Acc@5, Acc@10 | Any GT function in top-k (relaxed) / All GT functions in top-k (strict) |
| Module | Acc@5, Acc@10 | Any function in correct class in top-k |

---

## Localization Baselines

### HitMore — MLP Re-Ranker

Random Forest classifier trained on commit-history features. Ranks all files in the repository by vulnerability relevance.

```bash
cd Localization_baselines/HitMore/

# Full repo ranking (correct baseline mode)
python3 main.py --mode full_repo --limit 100

# Evaluate
python3 -c "
import json, sys
sys.path.insert(0, '../../Localization')
from evaluate import run_evaluation
run_evaluation('../Results/HitMore')
"
```

**How it works:** Extracts features from each repo file (edit frequency, recency, co-change with known-vulnerable files, file size, extension). Trains a RandomForest to score all files. Outputs ranked file list per CVE.

### RepoMem — Memory-Augmented Agent

LLM agent with repository memory (commit history, hotspots, BM25 search, issue links). Multi-turn tool-calling loop.

```bash
cd Localization_baselines/RepoMem/

# Build all RMS databases first
python3 run.py --build-all --max-commits 500

# Run localization
python3 run.py --limit 100

# Evaluate
python3 evaluate.py --results ../Results/RepoMem
```

**How it works:** Builds per-project SQLite memory store with commit metadata, hotspot files, and BM25 index. LLM agent uses 5 tools (view_code, search_code, examine_commit, search_issues, get_directory) in multi-turn loop. Outputs ranked files and functions.

### VanillaLLM — Pure LLM Baseline

Direct LLM call with no tools, no KG, no agent loop. Minimal prompt with only CVE report and directory listing.

```bash
cd Localization_baselines/VanillaLLM/

# Run localization
python3 run.py --limit 100

# Evaluate
python3 evaluate.py --results ../Results/VanillaLLM
```

**How it works:** Single LLM API call per CVE. Prompt contains only the vulnerability report and a flat directory listing. No commit history, no BM25, no issue links. Pure LLM reasoning ability test.

### RLocator — CodeBERT Similarity Ranking

Embeds CVE descriptions and source files using CodeBERT, ranks by cosine similarity.

```bash
cd Localization_baselines/

python3 baseline_rlocator.py --limit 100 --manifest ../Dataset/dataset_with_changed_files_filter.json
```

**How it works:** Encodes the CVE description text with CodeBERT. Encodes each source file's first N lines. Ranks files by cosine similarity between CVE embedding and file embedding.

---

## Explanation Baselines

### Coca-main — Context-Aware Vulnerability Detection + Explanation

Multi-detector framework (DeepWuKong, Devign, Reveal) with context-aware explanation generation.

```bash
cd Explanation_baselines/Coca-main/

# Preprocess source code
python3 preprocess/tokenize.py

# Train detectors
python3 models/detectors/DeepWuKong/train.py
python3 models/detectors/Devign/train.py
python3 models/detectors/Reveal/train.py

# Evaluate explanations
# See README.md in Coca-main/ for full workflow
```

**How it works:** Trains GNN-based vulnerability detectors (DeepWuKong, Devign, Reveal) on source code graphs. Generates explanations by propagating relevance scores backward through the GNN to identify critical code statements. Uses CodeBERT embeddings as node features.

### IVDetect — Inter-Procedural Vulnerability Detection + Explanation

Inter-procedural program dependency graph (PDG) + GNN vulnerability detector with statement-level explanation.

```bash
cd Explanation_baselines/IVDetect/

# Preprocess data
python3 gen_graphs.py

# Train and evaluate
python3 main.py --processed_dir data/ --out_dir result/
python3 main.py --processed_dir data/ --out_dir result/ -v  # evaluate only
```

**How it works:** Builds inter-procedural PDGs from source code (combining control flow, data flow, and call edges). Trains a GNN classifier to detect vulnerable functions. Statement-level explanations via gradient-based attribution on the PDG.

### cfexplainer — Counterfactual Explanation for Vulnerability Detection

GNN-based vulnerability detection with counterfactual explanation generation.

```bash
cd Explanation_baselines/cfexplainer/

# Preprocess data
python3 data_pre.py
python3 code_graph_gen.py
python3 graph_dataset.py

# Train and explain
python3 main.py --gnn_model GCNConv --epochs 100
```

**How it works:** Trains a GNN vulnerability detector, then generates counterfactual explanations by finding minimal graph perturbations (edge removals) that flip the prediction. Identifies which code edges are most critical for the vulnerability classification.

### unified_training — Unified Detector + Explainer Training Framework

Unified framework for training GNN detectors (GNN, IVDetect, Coca) with multiple explainers (GNNExplainer, cfexplainer).

```bash
cd Explanation_baselines/unified_training/

# Prebuild graphs
python3 prebuild_graphs.py
python3 prebuild_explain_graphs.py

# Train all detector + explainer combinations
bash run_all_explanations.sh

# Or run specific combination
python3 explain_localization.py --model gnn --explainer gnnexplainer --top-k 5 --limit 100
```

**How it works:** Prebuilds code graphs from source, then systematically trains all detector-explainer pairs. Supports: models (GNN/GCN, IVDetect PDG, Coca detectors), explainers (GNNExplainer gradient attribution, cfexplainer counterfactual). Outputs top-K statement-level explanations per CVE.

---

## Common Evaluation

All methods use the same evaluation framework from `Localization/evaluate.py`:

```bash
cd Localization/
python3 evaluate.py --results ../Results/{method_name}
```

Outputs per-method `evaluation_summary.json` and `evaluation_details.json` with file/function/module-level metrics.
