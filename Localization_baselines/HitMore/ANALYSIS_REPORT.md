# HitMore Baseline — Data Leakage & Experimental Validity Analysis

> Date: 2026-06-04 | Evaluator: Automated Pipeline Audit

---

## Executive Summary

**HitMore's reported 99.82% file-level success rate is an artifact of a fundamentally flawed evaluation methodology.** The test set construction in `dataset.py:build_dataset()` creates an artificially tiny candidate pool (average 6.4 files, 62.5% of CVEs have only 4 candidates). This makes the ranking task trivially easy and the reported metrics **not comparable** to VulnLocalization's real-vs-real evaluation (which ranks against hundreds to thousands of files per CVE).

**Verdict: NOT VALID** as a vulnerability localization baseline. The experimental validation does not meet academic paper robustness standards.

---

## 1. The Core Problem: Artificial Candidate Pool

### 1.1 How the Test Set Is Built (`HitMore/dataset.py`, lines 56-149)

```python
def build_dataset(limit=None, verbose=True):
    for entry in manifest:
        repo_files = list_repo_files(repo_path)        # ← max 200 files
        gt_files = set(gt.get("changed_files", []))
        
        # Match GT against repo files
        gt_files_normalized = {match GT to repo_files}
        
        # Negative sampling: only 3x GT count
        neg_files = [f for f in repo_files if f not in gt_files_normalized]
        n_neg = min(len(neg_files), len(gt_files_normalized) * 3)  # ← KEY LINE
        sampled_neg = random.sample(neg_files, n_neg)
```

Two critical design choices:

1. **`list_repo_files(repo_path, max_files=200)`** — Hard cap at 200 files. Real repos have 50–5000+ files.
2. **`n_neg = min(len(neg_files), len(gt_files_normalized) * 3)`** — Only 3× negatives per GT file.

### 1.2 Resulting Candidate Pool Distribution

| Candidate Pool Size | CVE Count | Percentage | Effective Top-K Ceiling |
|---------------------|-----------|------------|------------------------|
| 4 files | 351 | 62.5% | Top-5 always hits |
| 6–8 files | 131 | 23.3% | Top-8 always hits |
| 9–12 files | 28 | 5.0% | |
| 15 files | 53 | 9.4% | Top-15 always hits |

- **Mean candidate pool: 6.4 files**
- **Mean GT files per CVE: 2.1**
- **85.5% of CVEs have ≤8 candidates**

### 1.3 Why This Makes Success Rate Meaningless

The "Success Rate" metric checks: does ANY of the top-15 predicted files match ANY GT file? With a candidate pool of 4–15 files, this is nearly guaranteed:

- For 351 CVEs with 4 candidates: **random Top-5 = 100%** (you'd need to rank 5 items from a pool of 4)
- For 53 CVEs with 15 candidates: **random Top-15 = 100%** (exhaustive search)
- Even a **completely random** classifier would achieve ~70–80% success rate under this setup

The actual 99.82% success rate is **barely above what trivial baselines (like "return all candidates") would achieve**.

---

## 2. The Only Meaningful Metric: Top-1 Accuracy

Stripping away the inflated metrics, the only measure with any signal is **Top-1 accuracy**:

| Metric | HitMore | Random Baseline | Notes |
|--------|---------|-----------------|-------|
| Success Rate | 99.82% | ~85% | Meaningless — Top-15 covers entire candidate pool |
| Top-5 Accuracy | 95.91% | ~100% | Mathematically guaranteed for 351 CVEs (pool ≤ 4) |
| Top-3 Accuracy | 77.40% | ~50% | Heavily inflated by small pools |
| **Top-1 Accuracy** | **45.37%** | ~17% (avg pool 6.4) | **Only partially meaningful metric** |

But even Top-1 is inflated:
- For 4-candidate CVEs, random Top-1 = 25%. HitMore achieves 46.72%.
- For 15-candidate CVEs, random Top-1 = 7%. HitMore achieves 48.75%.

The model does learn *something*, but the **absolute performance is unknown** because the candidate pool is fundamentally unrepresentative of the real ranking challenge.

---

## 3. Why the Numbers Look "Too Good" — Detailed Mechanism

### 3.1 Selection Bias

CVEs whose GT files happen to NOT be in the first 200 files returned by `os.walk()` are **silently excluded** (lines 113-115 of `dataset.py`):

```python
if not gt_files_normalized:
    skipped_no_files += 1
    continue
```

This creates a selection bias: only "easy" CVEs (where the GT file is in the first 200 alphabetically-ordered repo files) enter the evaluation.

### 3.2 Feature Leakage

The features `rel_filename_in_issue` and `rel_filename_noext_in_issue` (in `features_extract.py`, lines 316-317) directly encode whether the filename appears in the CVE issue text:

```python
features["rel_filename_in_issue"] = 1 if file_name.lower() in issue_text.lower() else 0
```

This is highly predictive of the GT file because CVEs describe the vulnerable component. The issue text frequently mentions the filename (e.g., "XSS in index.php"). In a tiny pool of 4 candidates where only the GT file has this property, the model achieves trivial separation.

### 3.3 Candidate Pool vs. Real Repo Sizes

| CVE | Real Source Files | Candidate Pool | Reduction Factor |
|-----|-------------------|----------------|-----------------|
| CVE-2013-7449 | 189+ | ~8 | 24× |
| CVE-2015-1862 | 159+ | ~8 | 20× |
| CVE-2015-3454 | 225+ | ~8 | 28× |
| CVE-2015-8080 | 361+ | ~8 | 45× |
| CVE-2015-8869 | 356+ | ~8 | 45× |
| CVE-2015-8927 | 569+ | ~8 | 71× |
| CVE-2015-8931 | 569+ | ~8 | 71× |

The model is tested on a search space **20–70× smaller** than the real one.

---

## 4. Comparison: What a Valid Evaluation Looks Like

### VulnLocalization's `evaluate.py`

- Loads predictions from `result.json` (pipeline output)
- Predictions contain **ranked list of ALL files/functions in the repo** (hundreds to thousands)
- GT extracted from `git diff` between fix commit and parent
- Metrics computed against **full repo** search space

### RLocator Baseline (`baseline_rlocator.py`)

- For each CVE, lists **ALL source files** in the repo (no cap)
- Ranks all files by CodeBERT cosine similarity
- Evaluates against **full repo** using the same `evaluate.py`

### HitMore Adaptation

- For each CVE, lists **max 200 files** from repo
- Creates tiny test set of **GT files + 3× random negatives**
- Only evaluates on this 4–15 candidate subset
- **NOT comparable** to the above methods

---

## 5. How This Passes a Casual Code Review

The codebase has several features that give an impression of rigor:

1. **Cross-project deduplication** (`hitmore_data_loader.py:dedup_against_vulnlocalization`): Removes HitMore training rows that overlap with test GT files. This is good practice and prevents one type of leakage.

2. **K-fold CV grouped by CVE** (`dataset.py:get_kfold_splits`): Prevents same-CVE leakage across folds.

3. **Evaluation metrics aligned with `evaluate.py`**: Uses identical fuzzy matching, NDCG, MAP, MRR calculations.

4. **The `max_files=200` cap** is documented as "to prevent blowup" which sounds like a reasonable performance optimization.

However, these surface-level checks miss the fundamental issue: **the ranking task itself is trivial because the candidate pool is tiny**. No amount of deduplication or cross-validation can fix a test set that doesn't represent the real problem.

---

## 6. Recommendations for Fix

To make HitMore a valid baseline:

### 6.1 Remove the Candidate Pool Cap

```python
# In list_repo_files, remove or greatly increase max_files
def list_repo_files(repo_path, max_files=None):  # None = all files
```

### 6.2 Rank Against All Files

Instead of constructing an artificial test set with 3:1 neg:pos ratio, the model should:
1. List ALL source files in the repo
2. Score ALL of them
3. Rank ALL of them
4. Evaluate against the full ranking

### 6.3 Alternative: Use the Same Evaluation Pipeline

The cleanest fix: have HitMore output `result.json` files in the same format as VulnLocalization's pipeline, then run the **same** `evaluate.py` on them. This ensures identical evaluation conditions.

```python
# Instead of building_dataset → compute_metrics internally:
for cve in manifest:
    all_files = list_all_repo_files(repo_path)
    scores = model.predict(all_files)
    ranked = sorted(zip(all_files, scores), key=lambda x: x[1], reverse=True)
    save_result_json(cve_id, ranked_files=ranked, ranked_funcs=extract_functions(ranked))

# Then:
# cd Explainable_Localization && python3 evaluate.py --results ../HitMore/output
```

### 6.4 Report Per-Pool-Size Metrics

If the small-pool approach is kept for some reason, metrics MUST be stratified by candidate pool size and reported separately. A "file success rate of 99.82% with average pool size 6.4" is fundamentally different from "file success rate of X% with average pool size 500."

---

## 7. Conclusion

| Criteria | Assessment |
|----------|-----------|
| Data leakage (train→test) | No — dedup is properly implemented |
| Test set representativeness | **FAIL** — Candidate pool is 20–70× smaller than real repo |
| Metric validity | **FAIL** — Success rate and Top-5 are mathematically guaranteed for most CVEs |
| Comparability to VulnLocalization | **FAIL** — Different evaluation protocol (4–15 candidates vs. full repo) |
| Academic robustness | **FAIL** — Would not pass peer review for a localization paper |

**The only valid metric from this experiment is Top-1 accuracy (~45%), but even that is inflated by the tiny candidate pool.** The function-level metrics (36.62% success rate) suffer from the same issues.

The HitMore adaptation is NOT usable as a baseline in its current form. The evaluation protocol must be redesigned to rank against the full repository, matching the conditions used by VulnLocalization's own evaluation (`evaluate.py`).
