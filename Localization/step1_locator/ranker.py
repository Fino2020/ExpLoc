"""
Ranker — evidence-weighted scoring and deduplication.

Post-processes agent output:
  - Merges single-pass and multi-turn predictions
  - Deduplicates by file path (keep highest score)
  - Normalizes scores to [0.10, 1.00] range
  - Evidence-weighted boosting for multi-source agreement
"""

from typing import Dict, List


def _normalize_pred(pred) -> dict:
    """Coerce a prediction element into a proper dict with 'file' and 'score' keys."""
    if isinstance(pred, str):
        return {"file": pred, "score": 0}
    if not isinstance(pred, dict):
        return {}
    file_val = pred.get("file", "")
    if isinstance(file_val, dict):
        file_val = file_val.get("file", file_val.get("path", ""))
    pred = dict(pred)
    pred["file"] = str(file_val)
    return pred


def deduplicate_files(predictions: List[dict]) -> List[dict]:
    """Deduplicate file predictions by path, keeping highest score."""
    seen: Dict[str, dict] = {}
    for raw in predictions:
        pred = _normalize_pred(raw)
        fpath = pred.get("file", "").strip()
        if not fpath:
            continue
        # Strip ./ and ../ path prefixes only (not leading dots from dotfiles)
        while fpath.startswith("./") or fpath.startswith("../"):
            if fpath.startswith("./"):
                fpath = fpath[2:]
            else:
                fpath = fpath[3:]
        fpath = fpath.replace("\\", "/")
        if fpath not in seen or pred.get("score", 0) > seen[fpath].get("score", 0):
            seen[fpath] = pred
            seen[fpath]["file"] = fpath
    return sorted(seen.values(), key=lambda x: -x.get("score", 0))


def deduplicate_functions(predictions: List[dict]) -> List[dict]:
    """Deduplicate function predictions by (file, function) key."""
    seen: Dict[str, dict] = {}
    for raw in predictions:
        pred = _normalize_pred(raw)
        fname = pred.get("function", "").strip()
        fpath = pred.get("file", "").strip()
        if not fname:
            continue
        # Strip ./ and ../ path prefixes only
        while fpath.startswith("./") or fpath.startswith("../"):
            if fpath.startswith("./"):
                fpath = fpath[2:]
            else:
                fpath = fpath[3:]
        fpath = fpath.replace("\\", "/")
        key = f"{fpath}:{fname}"
        if key not in seen or pred.get("score", 0) > seen[key].get("score", 0):
            seen[key] = pred
            seen[key]["function"] = fname
            seen[key]["file"] = fpath
    return sorted(seen.values(), key=lambda x: -x.get("score", 0))


def normalize_scores(predictions: List[dict], key: str = "score") -> List[dict]:
    """Normalize scores to [0.10, 1.00] range using min-max scaling."""
    if not predictions:
        return predictions

    scores = [p.get(key, 0) for p in predictions]
    min_s, max_s = min(scores), max(scores)

    if max_s == min_s:
        for p in predictions:
            p[key] = 0.50
        return predictions

    for p in predictions:
        s = p.get(key, 0)
        p[key] = round(0.10 + 0.90 * (s - min_s) / (max_s - min_s), 4)

    return predictions


def boost_by_evidence(
    predictions: List[dict],
    boost_factor: float = 0.10,
) -> List[dict]:
    """Boost scores for predictions with multiple evidence sources.

    +boost_factor for each additional evidence type beyond the first.
    """
    for pred in predictions:
        evidence = pred.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}
        matching_issues = evidence.get("matching_issues", [])
        matching_commits = evidence.get("matching_commits", [])

        sources = 0
        if matching_issues:
            sources += 1
        if matching_commits:
            sources += 1

        if sources > 1:
            pred["score"] = min(1.0, round(pred.get("score", 0) + boost_factor * (sources - 1), 4))

    # Re-sort
    predictions.sort(key=lambda x: -x.get("score", 0))
    return predictions


def rank_results(
    files: List[dict],
    functions: List[dict],
    normalize: bool = True,
    evidence_boost: bool = True,
) -> dict:
    """Rank and deduplicate agent output.

    Returns dict with vulnerable_files and vulnerable_functions,
    each deduplicated, optionally normalized, and evidence-boosted.
    """
    files = deduplicate_files(files)
    functions = deduplicate_functions(functions)

    if normalize:
        files = normalize_scores(files)
        functions = normalize_scores(functions)

    if evidence_boost:
        files = boost_by_evidence(files)
        functions = boost_by_evidence(functions)

    return {
        "vulnerable_files": files,
        "vulnerable_functions": functions,
    }
