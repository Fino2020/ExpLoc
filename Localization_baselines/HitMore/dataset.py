"""
Dataset preparation: create labeled (CVE, file) pairs from GT cache.
Adapted from HitMore's data labeling pipeline (readMergedRecLists.py).
"""

import json
import os
import re
import random
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import KFold

from HitMore.config import MANIFEST_PATH, GT_DIR, RANDOM_SEED, N_FOLDS
from HitMore.features_extract import extract_all_features

random.seed(RANDOM_SEED)


def load_manifest():
    """Load full manifest with issue data and GT."""
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)
    return manifest


def load_gt(cve_id):
    """Load GT for a CVE from Dataset/GT/ cache."""
    gt_path = os.path.join(GT_DIR, f"{cve_id}.json")
    if not os.path.exists(gt_path):
        return None
    with open(gt_path, "r") as f:
        return json.load(f)


def list_repo_files(repo_path, max_files=None):
    """List all source files in a repo.

    Args:
        repo_path: absolute path to the repo
        max_files: if set, cap at this many files (None = unlimited — correct for eval)
    """
    if not repo_path or not os.path.isdir(repo_path):
        return []
    files = []
    skip_dirs = {".git", "__pycache__", "node_modules", ".svn", ".hg",
                 "vendor", "third_party", "thirdparty", "build", "dist",
                 ".idea", ".vscode", "target", ".mvn", ".gradle"}
    # Also skip hidden dirs (start with .)
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for fname in filenames:
            # Skip hidden files, binary files, and large files
            if fname.startswith("."):
                continue
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > 1_000_000:  # skip >1MB
                    continue
            except OSError:
                continue
            rel_path = os.path.relpath(fpath, repo_path)
            files.append(rel_path)
            if max_files and len(files) >= max_files:
                return files
    return files


def list_source_files_only(repo_path, max_files=None):
    """List only source-code files (filtered by extension)."""
    src_exts = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh",
                ".java", ".js", ".jsx", ".mjs", ".ts", ".tsx",
                ".py", ".pyx", ".php", ".phtml", ".go", ".rs", ".rb",
                ".pl", ".pm", ".swift", ".kt", ".kts", ".scala", ".cs",
                ".sh", ".bash", ".sql", ".psql"}
    all_files = list_repo_files(repo_path, max_files=max_files)
    return [f for f in all_files if os.path.splitext(f)[1].lower() in src_exts]


def build_dataset(limit=None, verbose=True):
    """
    Build labeled dataset of (CVE, file) pairs.

    For each CVE:
      - GT files → positive samples (label=1)
      - Non-GT files from same repo → negative samples (label=0)
      - Negative sampling: up to 3x positive count
    """
    manifest = load_manifest()
    if limit:
        manifest = manifest[:limit]

    rows = []
    skipped_no_repo = 0
    skipped_no_gt = 0
    skipped_no_files = 0

    for i, entry in enumerate(manifest):
        cve_id = entry.get("cve_id")
        issue_list = entry.get("issue_list", [])
        issue_title = issue_list[0].get("title", "") if issue_list else ""
        issue_body = issue_list[0].get("body", "") if issue_list else ""
        language = entry.get("language", "unknown")
        repo_path = entry.get("repo_path", "")

        # Load GT
        gt = load_gt(cve_id)
        if not gt:
            skipped_no_gt += 1
            continue

        gt_files = set(gt.get("changed_files", []))
        if not gt_files:
            skipped_no_gt += 1
            continue

        # List repo files
        repo_files = list_repo_files(repo_path)
        if not repo_files:
            skipped_no_repo += 1
            continue

        # Normalize GT file paths to relative
        gt_files_normalized = set()
        for gf in gt_files:
            for rf in repo_files:
                if rf.endswith(gf) or gf.endswith(rf) or os.path.basename(rf) == os.path.basename(gf):
                    gt_files_normalized.add(rf)
                    break
            else:
                # Direct match: check if any repo file contains the GT path
                for rf in repo_files:
                    if gf in rf or rf in gf:
                        gt_files_normalized.add(rf)
                        break

        if not gt_files_normalized:
            skipped_no_files += 1
            continue

        # Negative files: all repo files not in GT
        neg_files = [f for f in repo_files if f not in gt_files_normalized]
        n_neg = min(len(neg_files), len(gt_files_normalized) * 3)
        sampled_neg = random.sample(neg_files, n_neg) if n_neg > 0 else []

        # GT functions from cache
        gt_funcs_list = gt.get("changed_functions", [])

        # Build rows
        for fpath in gt_files_normalized:
            feats = extract_all_features(issue_title, issue_body, fpath, language)
            feats["cve_id"] = cve_id
            feats["file_path"] = fpath
            feats["label"] = 1
            feats["_gt_funcs"] = json.dumps(gt_funcs_list)
            rows.append(feats)

        for fpath in sampled_neg:
            feats = extract_all_features(issue_title, issue_body, fpath, language)
            feats["cve_id"] = cve_id
            feats["file_path"] = fpath
            feats["label"] = 0
            feats["_gt_funcs"] = json.dumps(gt_funcs_list)
            rows.append(feats)

        if verbose and (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(manifest)} CVEs, rows={len(rows)}")

    print(f"\nDataset built: {len(rows)} rows")
    print(f"  Skipped: no-repo={skipped_no_repo}, no-gt={skipped_no_gt}, no-match={skipped_no_files}")

    df = pd.DataFrame(rows)
    return df


def prepare_features(df):
    """
    Convert raw feature DataFrame to ML-ready X, y.
    Handles categorical encoding and normalization.
    """
    y = df["label"].values
    info_cols = ["cve_id", "file_path", "label", "file_name", "_gt_funcs"]

    # Drop known non-numeric / leaky columns (including prefixed variants from extraction)
    drop_patterns = info_cols + ["file_name", "file_extension", "file_file_name", "br_file_name",
                                  "meta_cwe_id", "meta_language"]
    drop_cols = [c for c in drop_patterns if c in df.columns]
    X = df.drop(columns=drop_cols, errors="ignore")

    # Encode any remaining categorical string columns
    for col in list(X.columns):
        if X[col].dtype == object:
            try:
                X[col] = X[col].astype(float)
            except (ValueError, TypeError):
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))

    # Fill NaN
    X = X.fillna(0)

    # Ensure all columns are numeric — force-convert any remaining strings
    non_numeric = [c for c in X.columns if X[c].dtype == object]
    if non_numeric:
        print(f"WARNING: dropping non-numeric columns: {non_numeric}")
        X = X.drop(columns=non_numeric)

    # Double-check: try converting every column to float32
    for col in list(X.columns):
        try:
            X[col] = X[col].astype(np.float32)
        except (ValueError, TypeError):
            print(f"WARNING: force-dropping unconvertible column: {col}")
            X = X.drop(columns=[col])

    # Normalize
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    feature_names = list(X.columns)

    print(f"Feature matrix: {X_scaled.shape[0]} samples x {X_scaled.shape[1]} features")
    pos = sum(y == 1)
    neg = sum(y == 0)
    print(f"Labels: {pos} positive, {neg} negative (ratio={pos / max(neg, 1):.2f})")

    return X_scaled, y, feature_names, scaler


def get_kfold_splits(df, n_folds=N_FOLDS):
    """
    Create K-fold splits grouped by CVE (so same CVE doesn't leak across folds).
    """
    cve_ids = df["cve_id"].unique()
    kf = KFold(n_splits=n_folds, shuffle=True, random_state=RANDOM_SEED)

    for train_cve_idx, test_cve_idx in kf.split(cve_ids):
        train_cves = set(cve_ids[train_cve_idx])
        test_cves = set(cve_ids[test_cve_idx])

        train_df = df[df["cve_id"].isin(train_cves)]
        test_df = df[df["cve_id"].isin(test_cves)]

        yield train_df, test_df


def build_full_candidates(limit=None, source_only=True, verbose=True):
    """Build full-repo candidate list per CVE — NO negative sampling.

    This is the correct evaluation protocol: every CVE is evaluated against
    ALL files in its repo (or all source files if source_only=True),
    matching VulnLocalization's evaluate.py conditions.

    Returns:
        List of dicts: {cve_id, issue_title, issue_body, language, repo_path,
                        files: [(file_path, feature_dict), ...],
                        gt_files: set, gt_funcs: list}
    """
    manifest = load_manifest()
    if limit:
        manifest = manifest[:limit]

    cvcs = []
    skipped_no_repo = 0
    skipped_no_gt = 0
    skipped_no_match = 0

    list_fn = list_source_files_only if source_only else list_repo_files

    for i, entry in enumerate(manifest):
        cve_id = entry.get("cve_id")
        issue_list = entry.get("issue_list", [])
        issue_title = issue_list[0].get("title", "") if issue_list else ""
        issue_body = issue_list[0].get("body", "") if issue_list else ""
        language = entry.get("language", "unknown")
        repo_path = entry.get("repo_path", "")

        gt = load_gt(cve_id)
        if not gt:
            skipped_no_gt += 1
            continue

        gt_files_raw = set(gt.get("changed_files", []))
        if not gt_files_raw:
            skipped_no_gt += 1
            continue

        repo_files = list_fn(repo_path)  # ALL files, no cap
        if not repo_files:
            skipped_no_repo += 1
            continue

        # Normalize GT against repo
        gt_files_normalized = set()
        for gf in gt_files_raw:
            gf_lower = gf.lower().rstrip(".")
            for rf in repo_files:
                rf_lower = rf.lower()
                if (rf_lower.endswith(gf_lower) or gf_lower.endswith(rf_lower)
                        or os.path.basename(rf_lower) == os.path.basename(gf_lower)):
                    gt_files_normalized.add(rf)
                    break
            else:
                for rf in repo_files:
                    if gf_lower in rf.lower() or rf.lower() in gf_lower:
                        gt_files_normalized.add(rf)
                        break

        if not gt_files_normalized:
            skipped_no_match += 1
            continue

        # Extract features for ALL files
        file_features = []
        for fpath in repo_files:
            feats = extract_all_features(issue_title, issue_body, fpath, language)
            file_features.append((fpath, feats))

        cvcs.append({
            "cve_id": cve_id,
            "issue_title": issue_title,
            "issue_body": issue_body,
            "language": language,
            "repo_path": repo_path,
            "files": file_features,
            "gt_files": gt_files_normalized,
            "gt_funcs": gt.get("changed_functions", []),
        })

        if verbose and (i + 1) % 50 == 0:
            avg_files = sum(len(c["files"]) for c in cvcs) / len(cvcs)
            print(f"  [{i+1}/{len(manifest)}] {cve_id}: {len(repo_files)} files, "
                  f"{len(gt_files_normalized)} GT | avg={avg_files:.0f} files/CVE")

    if verbose:
        avg_files = sum(len(c["files"]) for c in cvcs) / max(len(cvcs), 1)
        print(f"\nFull-repo candidates: {len(cvcs)} CVEs, avg {avg_files:.0f} files/CVE")
        print(f"  Skipped: no-repo={skipped_no_repo}, no-gt={skipped_no_gt}, "
              f"no-match={skipped_no_match}")

    return cvcs


def extract_function_names_from_file(file_path, content=None, repo_path=None):
    """Extract function/method names from source code via tree-sitter AST.

    Uses the same tree-sitter infrastructure as VulnLocalization's
    tree_sitter_gt.py for consistency.

    Args:
        file_path: relative file path (used to detect language from extension)
        content: source code text (if None, reads from repo_path/file_path)
        repo_path: absolute repo root path

    Returns:
        Deduplicated list of function names in declaration order.
    """
    if content is None and repo_path:
        full_path = os.path.join(repo_path, file_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []
    if not content:
        return []

    # Use tree-sitter from VulnLocalization's own infrastructure
    try:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Explainable_Localization"))
        from tree_sitter_gt import _extract_functions_ast, detect_lang

        lang = detect_lang(file_path)
        if lang == "unknown":
            return []

        func_map = _extract_functions_ast(content, lang)
        # func_map is {name: [(start_line, end_line), ...]}
        # Return names in order of first appearance
        names = list(func_map.keys())
        return names
    except ImportError:
        pass

    return []


def build_result_json(cve_entry, ranked_files, ranked_funcs, elapsed_sec=0.0):
    """Build VulnLocalization-compatible result.json dict.

    Args:
        cve_entry: dict from build_full_candidates()
        ranked_files: [(file_path, score), ...] sorted by score descending
        ranked_funcs: [(func_name, score), ...] sorted by score descending
        elapsed_sec: inference time in seconds
    """
    return {
        "cve_id": cve_entry["cve_id"],
        "owner": "",
        "project": "",
        "language": cve_entry.get("language", ""),
        "issue_title": cve_entry.get("issue_title", ""),
        "issue_body": (cve_entry.get("issue_body", "") or "")[:2000],
        "elapsed_seconds": round(elapsed_sec, 1),
        "baseline": "HitMore-MLP-FullRepo",
        "pipeline": {
            "_ranked_files": [[fp, round(float(s), 6)] for fp, s in ranked_files],
            "_ranked_functions": [[fn, round(float(s), 6)] for fn, s in ranked_funcs[:100]],
        },
    }


if __name__ == "__main__":
    print("Building dataset...")
    df = build_dataset(limit=50)
    print(f"\nColumns: {list(df.columns)}")
    print(f"Label distribution:\n{df['label'].value_counts()}")
    print(f"\nSample:\n{df.head(2).to_string()}")
