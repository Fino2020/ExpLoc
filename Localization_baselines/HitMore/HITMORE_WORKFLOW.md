# HitMore Workflow Report

> Baseline analysis for VulnLocalization comparison | 2026-06-03

---

## 1. Overview

HitMore is a **bug localization re-ranking system** from the paper *"HitMore: A Multi-Feature Ensemble Approach for Bug Localization"*. It takes initial file recommendations from existing bug localization tools and uses machine learning (ensemble RandomForest) to re-rank them for higher accuracy.

**Core idea**: Existing tools (Amalgam, BugLocator, Blizzard) produce noisy top-20 file rankings. HitMore extracts 122 features about each (bug report, candidate file, report-file relation) pair, then trains a RandomForest to predict which files are truly buggy. The result is a re-ranked list with significantly improved Hit@K metrics.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         STEP 1: Data Preparation                 │
│                                                                   │
│  Amalgam top-20 ─┐                                               │
│  BugLocator top-20 ├──► mergeRecLists ──► label with GT ──► CSV  │
│  Blizzard top-20 ─┘                                               │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      STEP 2: Feature Extraction + ML             │
│                                                                   │
│  ┌───────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │ Bug Report (28)   │  │ Buggy File (77)  │  │ Relation (18) │ │
│  │                   │  │                  │  │               │ │
│  │ • Stack traces    │  │ • Readability    │  │ • Similarity  │ │
│  │ • Code snippets   │  │ • NDEV (#devs)   │  │ • Topic (LDA) │ │
│  │ • Patch presence  │  │ • Comments cons. │  │ • Semantics   │ │
│  │ • Screenshots     │  │ • Bug freq/recen │  │ • Overlap     │ │
│  │ • Readability     │  │ • DAF/MAF        │  │ • Collab filt │ │
│  │ • Reporter info   │  │ • Scattering     │  │ • API sim     │ │
│  │                   │  │ • CodeComplexity │  │               │ │
│  └───────────────────┘  └──────────────────┘  └───────────────┘ │
│                            │          │            │              │
│                            └──────────┼────────────┘              │
│                                       ▼                           │
│                        ┌──────────────────────┐                   │
│                        │  RandomForest (cuML) │                   │
│                        │  GPU-accelerated     │                   │
│                        │  SMOTE oversampling  │                   │
│                        │  5-fold CV (by bug)  │                   │
│                        └──────────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                   STEP 3: Optimization (optional)                 │
│                                                                   │
│  Java Understand DB → butterfly graph → control/data flow        │
│  → cooccurrence analysis → merged re-ranked lists                │
│  (Not adapted in VulnLocalization version)                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Pipeline

### 3.1 Step 1: Data Preparation

**Input**: 6 Java projects (zookeeper, openjpa, Tomcat, aspectj, hibernate, lucene)

**Process**:
1. Three existing approaches produce initial rankings:
   - **Amalgam**: Text similarity + stack trace analysis
   - **BugLocator**: TF-IDF + structural features
   - **Blizzard**: Collaborative filtering
2. For each bug ID, top-20 recommended files from each approach are collected
3. Each (bug_id, file_path) pair is labeled: `1` if file is in ground truth (fixed in bug-fixing commit), `0` otherwise
4. Labeled data is merged into a single CSV: `mergedRecList.csv`
5. Data is split into 5-fold cross-validation (grouped by bug_id to prevent test-set leakage)

**Key files**:
- `model/readMergedRecLists.py` — labeling logic
- `model/EnsembleMethod.py` — fold splitting + model training
- `configx/configx.py` — dataset paths per project

**Data format** (`mergedRecList.csv`):
```
id, bugId, rank_0, score_0, path_0, rank_1, path_1, score_1, rank_2, path_2, label
```
Where `_0`=Amalgam, `_1`=BugLocator, `_2`=Blizzard.

### 3.2 Step 2: Feature Extraction

Three feature categories are extracted per (bug_report, candidate_file) pair. All features are precomputed and stored as CSV split by fold.

#### A. Bug Report Features (28 features)

| Feature | Description | Source |
|---------|-------------|--------|
| `hasStackTraces` | Java stack trace regex (`at xxx.java:N`) | `BugReportFeatures.py` |
| `hasStack` | Extended stack detection (ENTRY/SUBENTRY/STACK tags) | `BugReportFeatures.py` |
| `hasCode` | Code snippet detection (class/function def, if/for, braces) | `BugReportFeatures.py` |
| `hasPatch` | Diff/patch text detection (`---/+++/@@` or "patch"/"fix") | `BugReportFeatures.py` |
| `hasScreenshot` | Screenshot-related words (window, screenshot, png, jpg...) | `BugReportFeatures.py` |
| Reporter features | Reporter name, commit count, assign count, valid commit count | computed from XML |
| Readability | Flesch-Kincaid, SMOG, Gunning Fog, Coleman-Liau, ARI, LIX | `readability/` |
| Keywords | Project-specific keyword lists (per-dataset curated) | `configx/configx.py` |

#### B. Buggy File Features (77 features)

| Feature Group | Description | Source |
|---------------|-------------|--------|
| Code Readability | Lines of code, comment ratio, identifier length, readability scores | `readability/code_readability.py`, `getCfReadability.py` |
| NDEV | Number of developers who modified this file | `NDEV.py` |
| Comments-Code Consistency | Ratio of comments to code | `code_and_comments_consistency.py` |
| Bug-Fixing Recency/Frequency | How recently and frequently the file was fixed | `features_collaborative.py` (using `XMLToDictionary.py`) |
| DAF/MAF | Developer Activity Factor / Module Activity Factor | `DAF_MAF.py` |
| Developer Scattering | Structural scattering (files touched by same developer), Semantic scattering (topic-based) | `structural_and_semantic_scattering.py` |
| Code Complexity | CK metrics (WMC, DIT, NOC, CBO, RFC, LCOM, Ca, Ce, NPM, LCOM3, etc.) via `CK` tool | `getCodeComplexity.py` |
| API Similarity | Comparison of API calls in bug report vs. file | `getAPIsim.py` |

#### C. Relation Features (18 features)

| Feature Group | Description | Source |
|---------------|-------------|--------|
| Developer-Reporter Overlap | Are the reporter and file developers the same people? | `overlap.py` |
| Collaborative Filtering Score | User-based CF for buggy file prediction | `features_collaborative.py` |
| Class Name Similarity | Cosine similarity between bug report and class names | `features_collaborative.py` |
| Surface Lexical Similarity | Tokenized Jaccard + TF-IDF cosine | `similarity.py` |
| Semantic Similarity | Word2Vec (GoogleNews-vectors-negative300) WMD distance | `similarity.py` (semantic_sim) |
| API-Enriched Lexical Similarity | API names extracted from both sides for similarity | `getAPIsim.py` (from LR fold) |
| Topic Similarity | LDA topic modeling (gensim) for bug report vs. file | `topicSimilarity.py` |

### 3.3 Machine Learning

**Model**: RandomForest (GPU-accelerated via RAPIDS `cuML`)

**Configuration** (per-dataset hyperparameters):
```python
zookeeper_models = {
    'Random Forest': cuRandomForestClassifier(max_features=0.5, max_samples=0.1),
    'SVM': cuSVC(C=4, gamma=1/64, kernel='rbf'),
    'Naive Bayes': cuGaussianNB(var_smoothing=0.1),
    'Logistic Regression': cuLogisticRegression(C=7)
}
```
Each dataset (zookeeper, openjpa, Tomcat, aspectj, hibernate, lucene) has its own tuned hyperparameters.

**Training procedure**:
1. 5-fold cross-validation (PredefinedSplit by bug_id to prevent leakage)
2. SMOTE oversampling (handles class imbalance: typically ~1:3 positive:negative)
3. MinMax scaling (feature_range 0-1)
4. Per-fold: train on 4 folds, predict on 1 fold
5. Evaluation: Hit@K (1,5,10,15,20), Accuracy@K, precision/recall/f1

**Evaluation metrics**:
- Per-fold: accuracy, precision (weighted), recall (weighted), f1 (weighted), AUC
- Per-bug: Hit@K — "does any correctly predicted file appear in top-K?"
- Aggregate: 5-fold average of all metrics
- Separate evaluation by time-split (80% train / 20% test by bug creation date)

**Alternative models** (for comparison):
- AdaBoost with DecisionTreeRegressor (base model for ensemble)
- XGBoost (XGBRegressor) with tuned hyperparameters

### 3.4 Step 3: Optimization (Java Understand DB)

Requires the commercial tool *"Java Understand"* (SciTools). Steps:
1. Create Understand DB (`scripts/createUdb.sh`)
2. Generate butterfly graph of call relationships (`generate_butterfly.py`)
3. Control flow / data flow analysis (`controlFlow_and_dataFlow.py`)
4. Cooccurrence analysis (`cooccurrence.py`)
5. Merge and re-rank (`merged_reranked_reclists.py`)

This step is **not portable** to VulnLocalization (proprietary tool + Java-only).

---

## 4. Key Dependencies

| Dependency | Purpose |
|------------|---------|
| `cuml` (RAPIDS) | GPU-accelerated RandomForest, SVM, NaiveBayes, LogisticRegression |
| `cupy` | GPU array operations (CuPy arrays for cuML) |
| `scikit-learn` | Preprocessing, metrics, SMOTE pipeline |
| `imbalanced-learn` | SMOTE oversampling |
| `nltk` | Tokenization, stemming, stopwords |
| `gensim` | LDA topic modeling, Word2Vec similarity |
| `pandas` | Data manipulation |
| `xgboost` | Alternative ML model |
| `Java Understand` | Step 3 call-graph analysis (commercial, not portable) |

**GPU requirement**: cuML requires NVIDIA GPU + CUDA + RAPIDS. CPU fallback uses sklearn.

---

## 5. Dataset Format

### 5.1 Bug Info (`merged4tools`)

Custom format with `邹` (rare Chinese character) as delimiter:
```
bugId邹fixedCmit邹cmitUnixTime邹allFixedFiles邹addFiles邹...邹description
```

### 5.2 Bug Reports (XML)

```xml
<item>
  <id>1</id>
  <summary>Bug title</summary>
  <description>Bug description with code snippets, stack traces...</description>
  <patch>0|1</patch>
  <screenshots>0|1</screenshots>
  <reporter><name>username</name></reporter>
  <assignee><name>developer</name></assignee>
  <create_time>Fri, 21 Sep 2018 02:12:36 +0000</create_time>
  <resolve_time>Thu, 22 Nov 2018 16:56:24 +0000</resolve_time>
  <comments>
    <commenter><author>user1</author></commenter>
  </comments>
</item>
```

### 5.3 Initial Recommendations

Per-bug text files. Each line: `rank,file_path,score`
```
1,org/apache/zookeeper/server/ServerCnxn.java,0.95
2,org/apache/zookeeper/server/NIOServerCnxn.java,0.87
...
```

### 5.4 Ground Truth

```
bugId,SourceFile,Rank,Score
123,org/apache/zookeeper/server/quorum/Leader.java,1,0.92
```

---

## 6. Adapted VulnLocalization Version

### What's preserved:
- Binary classifier with class-weight imbalance handling
- Feature extraction concept: bug report features, file features, relation features
- Hit@K, MRR, NDCG, MAP ranking evaluation (aligned with evaluate.py)

### What's changed:
| Original | Adapted |
|----------|---------|
| GPU cuML RandomForest | GPU PyTorch MLP (CUDA 11.8, RTX 3070 Ti) |
| SMOTE oversampling | BCEWithLogitsLoss with pos_weight |
| 122 Java-specific features | 35 language-agnostic features |
| XML bug reports with 18 fields | XML bug reports (HitMore train) + JSON CVE manifest (test) |
| Pre-computed Amalgam/BugLocator/Blizzard top-20 | Merge-file-based (bugId, file) pairs from HitMore |
| 5-fold CV on same dataset | Cross-project transfer: train=HitMore (6 Java projects), test=VulnLocalization (886 CVEs) |
| Java-only (.java files) | Train: Java, Test: multi-language (C, Python, JS, Java, PHP, Go, Ruby...) |
| CK metrics + Java Understand DB | Not applicable (removed) |
| Per-project evaluation | Cross-project: train on 6 Java projects, test on 886 multi-lang CVEs |

### What's missing vs original:
- Collaborative filtering features (no developer/bug history data in manifest)
- CK/NDEV/DAF/MAF metrics (require Java-specific tooling)
- Semantic Word2Vec similarity (GoogleNews vectors 3.6GB, not practical)
- Topic LDA similarity (gensim — could be added but slow)
- Step 3 control/data flow optimization (Java Understand DB — commercial tool)

### Training pipeline:
1. Load HitMore merge files (244K lines across 6 datasets) → 67K unique (bugId, file) pairs
2. Label each pair via fuzzy match against GT res files
3. Extract 35 features (same as inference)
4. Dedup: remove rows whose file paths overlap VulnLocalization test GT (80 rows removed)
5. Train PyTorch MLP [256→128→64] on GPU with class weights
6. Evaluate on VulnLocalization CVEs using evaluate.py-aligned metrics

### Inference: File-level ranking per CVE
1. For each CVE, generate candidate files from repo
2. Extract same 35 features
3. Score with trained PyTorch MLP → rank by probability
4. Match against GT with 3-level fuzzy file matching + 5-level function matching

---

## 7. Feature Mapping: Original → Adapted

| Original HitMore Feature (122) | Adapted Feature (35) | Category |
|-------------------------------|---------------------|----------|
| br: hasStackTraces, hasStack | `br_has_stack_trace` | Bug Report |
| br: hasCode | `br_has_code` | Bug Report |
| br: hasPatch | `br_has_patch` | Bug Report |
| br: hasScreenshot | `br_has_screenshot` | Bug Report |
| br: readability scores | `br_readability`, `br_avg_word_len` | Bug Report |
| br: keyword density | `br_security_keyword_count` | Bug Report |
| br: reporter metrics | Not available (no developer data) | — |
| cf: code readability | Not available (no source parsing) | — |
| cf: NDEV, DAF, MAF | Not available (no git history) | — |
| cf: code complexity (CK) | `file_depth`, `file_name_len` | File |
| cf: file path analysis | `file_in_important_dir`, `file_path_security_score` | File |
| cf: language/type detection | `file_extension`, `file_matches_language`, `file_has_src_ext` | File |
| cf: test file detection | `file_is_test` | File |
| rel: surface lexical sim | `rel_jaccard`, `rel_token_overlap` | Relation |
| rel: semantic sim (WMD) | Not ported (GoogleNews 3.6GB) | — |
| rel: topic sim (LDA) | Not ported (slow) | — |
| rel: overlap (developer) | Not available | — |
| rel: filename match | `rel_filename_in_issue`, `rel_filename_noext_in_issue` | Relation |
| rel: directory match | `rel_dir_overlap` | Relation |
| meta: CWE, CVSS, language | `meta_cvss_score`, `meta_language` | Metadata |

---

## 8. Execution Commands

### Original HitMore
```bash
# Step 1: Label merged recommendation lists
python3 model/readMergedRecLists.py

# Step 2: Extract features + train ensemble model
python3 model/EnsembleMethod.py
# or for GPU RandomForest:
python3 model/hitMore_cuml_rf.py
```

### Adapted VulnLocalization Version
```bash
cd /mnt/d/Desktop/VulnLocalization

# Small test (100 samples/dataset from HitMore, 30 CVEs from VulnLocalization)
python3 -m HitMore.main --mode cross_project --limit 30 --train-samples 100

# Medium run (200 samples/dataset, 100 CVEs)
python3 -m HitMore.main --mode cross_project --limit 100 --train-samples 200

# Full run (all HitMore data, all 886 CVEs)
python3 -m HitMore.main --mode cross_project --limit 0 --train-samples 0

# K-fold CV on VulnLocalization only (no HitMore transfer)
python3 -m HitMore.main --mode kfold --limit 100

# Results: HitMore/output/evaluation_summary.json
# Model: HitMore/output/model/hitmore_mlp_gpu.pt
```
