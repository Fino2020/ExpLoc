"""
Evaluation module for the Localization pipeline.

Loads saved prediction results from OUTPUT_DIR/{CVE-ID}/result.json,
extracts ground truth from Dataset/GT/{CVE-ID}.json, and computes:

File-level:   Precision, Recall, F1, MRR, NDCG@15, MAP@15, Top-1/3/5, Success Rate
Function-level: Precision, Recall, F1, MRR, NDCG@15, MAP@15, Top-1/3/5, Success Rate

Reuses matching logic from Explainable_Localization/evaluate.py.
"""

import json
import math
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_LOCALIZATION_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Localization")
if _LOCALIZATION_DIR not in sys.path:
    sys.path.insert(0, _LOCALIZATION_DIR)

from shared.config import MANIFEST_PATH, OUTPUT_DIR, GT_DIR
from shared.gt_loader import GroundTruth, load_gt, filter_gt


# ---------------------------------------------------------------------------
# Prediction loading
# ---------------------------------------------------------------------------

@dataclass
class Predictions:
    cve_id: str
    top_files: List[str] = field(default_factory=list)
    top_functions: List[str] = field(default_factory=list)
    func_file_map: Dict[str, str] = field(default_factory=dict)
    file_scores: Dict[str, float] = field(default_factory=dict)
    func_scores: Dict[str, float] = field(default_factory=dict)


def load_predictions(results_dir: str, cve_id: str) -> Optional[Predictions]:
    """Load saved predictions from {results_dir}/{cve_id}/result.json."""
    json_path = os.path.join(results_dir, cve_id, "result.json")
    if not os.path.exists(json_path):
        return None

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    pred = Predictions(cve_id=cve_id)

    for vf in data.get("vulnerable_files", []):
        fpath = vf.get("file", "").strip().lstrip("./").replace("\\", "/")
        if fpath and fpath not in pred.top_files:
            pred.top_files.append(fpath)
            pred.file_scores[fpath] = float(vf.get("score", 0))

    for vf in data.get("vulnerable_functions", []):
        fname = vf.get("function", "").strip()
        fpath = vf.get("file", "").strip().lstrip("./").replace("\\", "/")
        if fname and fname not in pred.top_functions:
            pred.top_functions.append(fname)
            pred.func_file_map[fname] = fpath
            pred.func_scores[fname] = float(vf.get("score", 0))

    return pred


def apply_file_boost(predictions: Predictions, boost: float = 0.5) -> Predictions:
    """Re-rank functions by combining their score with their parent file's score.

    combined = (1 - boost) * func_score + boost * file_score

    A boost of 0.0 keeps original function ranking; 1.0 uses only file score.
    Returns a new Predictions with re-ordered functions.
    """
    import copy
    result = copy.deepcopy(predictions)

    # Match function → file score using the func_file_map
    def _combined_score(fname: str) -> float:
        func_s = predictions.func_scores.get(fname, 0)
        fpath = predictions.func_file_map.get(fname, "")
        file_s = predictions.file_scores.get(fpath, 0)
        return (1 - boost) * func_s + boost * file_s

    result.top_functions.sort(key=_combined_score, reverse=True)
    return result


# ---------------------------------------------------------------------------
# Fuzzy matching (same logic as Explainable_Localization/evaluate.py)
# ---------------------------------------------------------------------------

def _match_files(pred_files: List[str], gt_files: Set[str]) -> Set[str]:
    """Multi-level fuzzy file matching with extension variants."""
    matched: Set[str] = set()
    gt_lower = {gf.lower(): gf for gf in gt_files}

    gt_by_basename: Dict[str, Set[str]] = {}
    for gf in gt_files:
        bn = os.path.basename(gf).lower()
        gt_by_basename.setdefault(bn, set()).add(gf)
        # Also index by stem (basename without extension) for cross-extension matching
        stem = os.path.splitext(bn)[0]
        if stem != bn:
            gt_by_basename.setdefault(stem, set()).add(gf)

    for pf in pred_files:
        pf_lower = pf.lower()
        pf_bn = os.path.basename(pf).lower()
        pf_stem = os.path.splitext(pf_bn)[0].lower()

        # Level 1: Exact
        if pf_lower in gt_lower:
            matched.add(gt_lower[pf_lower])
            continue

        # Level 2: Suffix match
        found = False
        for gf_lower, gf in gt_lower.items():
            if pf_lower.endswith(gf_lower) or gf_lower.endswith(pf_lower):
                matched.add(gf)
                found = True
                break
        if found:
            continue

        # Level 3: Basename (exact match)
        if pf_bn in gt_by_basename:
            candidates = gt_by_basename[pf_bn]
            best = _pick_best_by_dir_overlap(pf_lower, candidates)
            if best:
                matched.add(best)
            else:
                matched.update(candidates)
            continue

        # Level 4: Stem match (cross-extension: .java↔.kt, .js↔.coffee, .h↔.c)
        if pf_stem and pf_stem in gt_by_basename:
            candidates = gt_by_basename[pf_stem]
            best = _pick_best_by_dir_overlap(pf_lower, candidates)
            if best:
                matched.add(best)
            else:
                matched.update(candidates)
            continue

        # Level 5: Partial directory + basename match
        for gf_lower, gf in gt_lower.items():
            gf_bn = os.path.basename(gf_lower)
            if pf_bn in gf_lower or gf_bn in pf_lower:
                matched.add(gf)
                break

    return matched


def _pick_best_by_dir_overlap(pf_lower: str, candidates: Set[str]) -> Optional[str]:
    """Pick best candidate by directory overlap score."""
    best = None
    best_score = -1
    pf_dirs = set(pf_lower.replace('\\', '/').split('/')[:-1])
    for c in candidates:
        c_dirs = set(c.lower().replace('\\', '/').split('/')[:-1])
        overlap = len(pf_dirs & c_dirs)
        if overlap > best_score:
            best_score = overlap
            best = c
    return best


def _normalize_function_name(name: str) -> str:
    """Normalize function name for matching."""
    name = name.strip().rstrip(';{}')
    if '\\' in name:
        name = name.rsplit('\\', 1)[-1]
    if '/' in name and ':' in name:
        parts = name.split(':')
        if len(parts) >= 2:
            name = parts[1]
    return name


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (0 if ca == cb else 1),
            ))
        prev = curr
    return prev[-1]


def _match_functions(pred_funcs: List[str], gt_funcs: Set[str]) -> Set[str]:
    """Multi-level fuzzy function matching."""
    matched: Set[str] = set()
    gt_lower = {f.lower(): f for f in gt_funcs}

    gt_short: Dict[str, Set[str]] = {}
    for f in gt_funcs:
        fl = f.lower()
        norm = _normalize_function_name(fl)
        gt_short.setdefault(norm, set()).add(f)
        last = fl.rsplit('::', 1)[-1].rsplit('.', 1)[-1].rsplit('->', 1)[-1]
        if last != norm:
            gt_short.setdefault(last, set()).add(f)

    for pf in pred_funcs:
        pf_lower = _normalize_function_name(pf.lower())

        # Level 1: Exact
        if pf_lower in gt_lower:
            matched.add(gt_lower[pf_lower])
            continue

        # Level 2: Short name
        if pf_lower in gt_short:
            matched.update(gt_short[pf_lower])
            continue

        # Level 3: Last component
        pf_last = pf_lower.rsplit('::', 1)[-1].rsplit('.', 1)[-1].rsplit('->', 1)[-1]
        if pf_last != pf_lower and pf_last in gt_short:
            matched.update(gt_short[pf_last])
            continue

        # Level 4: Substring
        for gf_lower, gf in gt_lower.items():
            gf_norm = _normalize_function_name(gf_lower)
            if pf_lower in gf_norm or gf_norm in pf_lower:
                min_len = min(len(pf_lower), len(gf_norm))
                if min_len >= 4 and (pf_lower[:3] == gf_norm[:3] or pf_lower[-3:] == gf_norm[-3:]):
                    matched.add(gf)
                    break

        # Level 5: Levenshtein
        if len(pf_lower) >= 3:
            best_match, best_dist = None, 999
            for gf_lower, gf in gt_lower.items():
                gf_norm = _normalize_function_name(gf_lower)
                dist = _levenshtein(pf_lower, gf_norm)
                max_len = max(len(pf_lower), len(gf_norm))
                ratio = dist / max_len if max_len > 0 else 1.0
                if dist <= 2 or ratio <= 0.3:
                    if dist < best_dist:
                        best_match, best_dist = gf, dist
            if best_match:
                matched.add(best_match)

    return matched


def _extract_module(func_name: str) -> str:
    """Extract class/module name from a function identifier.

    C++/Java/Scala:  ClassName::methodName  →  ClassName
    Python:           ClassName.method       →  ClassName
    PHP:              ClassName::methodName  →  ClassName
                      ClassName->methodName  →  ClassName
    JS/TS:            ClassName.prototype.method → ClassName
                      ClassName.method       →  ClassName
    Go:               package.Function       →  package
    Ruby:             Module::Class#method   →  Module::Class
    """
    if not func_name:
        return ""

    # Ruby: Module::Class#method or Module::Class.method
    ruby_m = re.match(r"^(.+)[#\.]([^#\.]+)$", func_name)
    if ruby_m and "::" in ruby_m.group(1):
        return ruby_m.group(1)

    # C++/Java/PHP: Class::method (but NOT PHP namespace\Class::method)
    # Split on :: and take the rightmost part before ::
    if "::" in func_name:
        parts = func_name.split("::")
        if len(parts) >= 2:
            # Strip PHP namespace prefix (backslash-separated)
            cls = parts[-2]
            if "\\" in cls:
                cls = cls.rsplit("\\", 1)[-1]
            return cls

    # PHP: Class->method
    if "->" in func_name:
        parts = func_name.split("->")
        return parts[0]

    # JS: ClassName.prototype.method
    if ".prototype." in func_name:
        return func_name.split(".prototype.")[0]

    # Go: package.Function / Python: module.function or Class.method
    if "." in func_name:
        parts = func_name.split(".")
        if len(parts) >= 2:
            return ".".join(parts[:-1])

    # No separator — function itself is the module
    return func_name


# ---------------------------------------------------------------------------
# NDCG & MAP
# ---------------------------------------------------------------------------

def _compute_dcg(relevance: List[int], k: int) -> float:
    dcg = 0.0
    for i in range(min(k, len(relevance))):
        rel = relevance[i]
        if rel > 0:
            dcg += rel / (math.log2(i + 2))
    return dcg


def _compute_ndcg(pred_list: List[str], gt_set: Set[str], match_fn, k: int = 15) -> float:
    if not gt_set:
        return 0.0
    relevance = []
    for pred in pred_list[:k]:
        matched = match_fn([pred], gt_set)
        relevance.append(1 if matched else 0)
    ideal_rel = sorted(relevance, reverse=True)
    dcg = _compute_dcg(relevance, k)
    idcg = _compute_dcg(ideal_rel, k)
    return dcg / idcg if idcg > 0 else 0.0


def _compute_map(pred_list: List[str], gt_set: Set[str], match_fn, k: int = 15) -> float:
    if not gt_set:
        return 0.0
    num_hits = 0
    sum_precisions = 0.0
    for i, pred in enumerate(pred_list[:k]):
        matched = match_fn([pred], gt_set)
        if matched:
            num_hits += 1
            sum_precisions += num_hits / (i + 1)
    return sum_precisions / min(len(gt_set), k) if num_hits > 0 else 0.0


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class CveMetrics:
    cve_id: str
    file_precision: float = 0.0
    file_recall: float = 0.0
    file_f1: float = 0.0
    file_mrr: float = 0.0
    file_ndcg: float = 0.0
    file_map: float = 0.0
    file_any_hit: int = 0
    file_top1: int = 0
    file_top3: int = 0
    file_top5: int = 0
    file_first_rank: int = -1

    # Strict Acc@k — all GT items must be in top-k (R-Precision)
    file_strict_acc1: int = 0
    file_strict_acc3: int = 0
    file_strict_acc5: int = 0
    file_strict_acc10: int = 0

    func_precision: float = 0.0
    func_recall: float = 0.0
    func_f1: float = 0.0
    func_mrr: float = 0.0
    func_ndcg: float = 0.0
    func_map: float = 0.0
    func_any_hit: int = 0
    func_top1: int = 0
    func_top3: int = 0
    func_top5: int = 0
    func_first_rank: int = -1

    # Strict Acc@k — all GT functions must be in top-k
    func_strict_acc5: int = 0
    func_strict_acc10: int = 0

    # Module-level — any predicted function in same module/class as any GT function
    module_acc1: int = 0
    module_acc3: int = 0
    module_acc5: int = 0
    module_acc10: int = 0

    gt_files: int = 0
    gt_funcs: int = 0
    pred_files: int = 0
    pred_funcs: int = 0
    matched_files: int = 0
    matched_funcs: int = 0


def compute_metrics(predictions: Predictions, gt: GroundTruth,
                    top_k_files: int = 15, top_k_funcs: int = 15) -> CveMetrics:
    """Compute all metrics for a single CVE."""
    m = CveMetrics(cve_id=predictions.cve_id)

    # File-level
    pred_files = predictions.top_files[:top_k_files]
    gt_files = gt.changed_files
    matched_files = _match_files(pred_files, gt_files)

    m.gt_files = len(gt_files)
    m.pred_files = len(pred_files)
    m.matched_files = len(matched_files)
    m.file_any_hit = 1 if matched_files else 0

    if pred_files:
        m.file_precision = len(matched_files) / len(pred_files)
    if gt_files:
        m.file_recall = len(matched_files) / len(gt_files)
    if m.file_precision + m.file_recall > 0:
        m.file_f1 = 2 * m.file_precision * m.file_recall / (m.file_precision + m.file_recall)

    for rank, pf in enumerate(pred_files, 1):
        if _match_files([pf], gt_files):
            m.file_mrr = 1.0 / rank
            m.file_first_rank = rank
            break

    if m.file_first_rank > 0:
        if m.file_first_rank <= 1:
            m.file_top1 = 1
        if m.file_first_rank <= 3:
            m.file_top3 = 1
        if m.file_first_rank <= 5:
            m.file_top5 = 1

    m.file_ndcg = _compute_ndcg(pred_files, gt_files, _match_files, k=15)
    m.file_map = _compute_map(pred_files, gt_files, _match_files, k=15)

    # File-level strict Acc@k: all GT files must be in top-k predictions
    if gt_files:
        for k in (1, 3, 5, 10):
            top_k_pred = predictions.top_files[:k]
            k_matched = _match_files(top_k_pred, gt_files)
            if len(k_matched) == len(gt_files):
                setattr(m, f"file_strict_acc{k}", 1)

    # Function-level
    pred_funcs = predictions.top_functions[:top_k_funcs]
    gt_funcs = gt.changed_functions
    matched_funcs = _match_functions(pred_funcs, gt_funcs)

    m.gt_funcs = len(gt_funcs)
    m.pred_funcs = len(pred_funcs)
    m.matched_funcs = len(matched_funcs)
    m.func_any_hit = 1 if matched_funcs else 0

    if pred_funcs:
        m.func_precision = len(matched_funcs) / len(pred_funcs)
    if gt_funcs:
        m.func_recall = len(matched_funcs) / len(gt_funcs)
    if m.func_precision + m.func_recall > 0:
        m.func_f1 = 2 * m.func_precision * m.func_recall / (m.func_precision + m.func_recall)

    for rank, pf in enumerate(pred_funcs, 1):
        if _match_functions([pf], gt_funcs):
            m.func_mrr = 1.0 / rank
            m.func_first_rank = rank
            break

    if m.func_first_rank > 0:
        if m.func_first_rank <= 1:
            m.func_top1 = 1
        if m.func_first_rank <= 3:
            m.func_top3 = 1
        if m.func_first_rank <= 5:
            m.func_top5 = 1

    m.func_ndcg = _compute_ndcg(pred_funcs, gt_funcs, _match_functions, k=15)
    m.func_map = _compute_map(pred_funcs, gt_funcs, _match_functions, k=15)

    # Function-level strict Acc@k: all GT functions must be in top-k predictions
    if gt_funcs:
        for k in (5, 10):
            top_k_pred = predictions.top_functions[:k]
            k_matched = _match_functions(top_k_pred, gt_funcs)
            if len(k_matched) == len(gt_funcs):
                setattr(m, f"func_strict_acc{k}", 1)

    # Module-level: per LocAgent — any predicted function in same module/class
    # as any GT function within top-k counts as a hit.
    if gt_funcs:
        gt_modules = {_extract_module(f) for f in gt_funcs}
        if gt_modules:
            for k in (1, 3, 5, 10):
                pred_modules = {_extract_module(f) for f in pred_funcs[:k]}
                if pred_modules & gt_modules:
                    setattr(m, f"module_acc{k}", 1)

    return m


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

@dataclass
class AggregateMetrics:
    total_cves: int = 0
    evaluated: int = 0
    skipped_no_gt: int = 0
    skipped_no_pred: int = 0

    file_precision: float = 0.0
    file_recall: float = 0.0
    file_f1: float = 0.0
    file_mrr: float = 0.0
    file_ndcg: float = 0.0
    file_map: float = 0.0
    file_success_rate: float = 0.0
    file_top1_acc: float = 0.0
    file_top3_acc: float = 0.0
    file_top5_acc: float = 0.0

    # Strict Acc@k — all GT files in top-k
    file_strict_acc1: float = 0.0
    file_strict_acc3: float = 0.0
    file_strict_acc5: float = 0.0
    file_strict_acc10: float = 0.0

    func_precision: float = 0.0
    func_recall: float = 0.0
    func_f1: float = 0.0
    func_mrr: float = 0.0
    func_ndcg: float = 0.0
    func_map: float = 0.0
    func_success_rate: float = 0.0
    func_top1_acc: float = 0.0
    func_top3_acc: float = 0.0
    func_top5_acc: float = 0.0

    # Strict Acc@k — all GT functions in top-k
    func_strict_acc5: float = 0.0
    func_strict_acc10: float = 0.0

    # Module-level — any predicted function in same module/class as any GT function
    module_acc1: float = 0.0
    module_acc3: float = 0.0
    module_acc5: float = 0.0
    module_acc10: float = 0.0

    per_cve: List[dict] = field(default_factory=list)


def compute_aggregate(cve_metrics_list: List[CveMetrics]) -> AggregateMetrics:
    agg = AggregateMetrics()
    agg.total_cves = len(cve_metrics_list)
    agg.evaluated = sum(1 for m in cve_metrics_list if m.gt_files > 0 or m.gt_funcs > 0)

    valid_file = [m for m in cve_metrics_list if m.gt_files > 0]
    valid_func = [m for m in cve_metrics_list if m.gt_funcs > 0]
    nf = max(len(valid_file), 1)
    ng = max(len(valid_func), 1)

    agg.file_precision = sum(m.file_precision for m in valid_file) / nf
    agg.file_recall = sum(m.file_recall for m in valid_file) / nf
    agg.file_f1 = sum(m.file_f1 for m in valid_file) / nf
    agg.file_mrr = sum(m.file_mrr for m in valid_file) / nf
    agg.file_ndcg = sum(m.file_ndcg for m in valid_file) / nf
    agg.file_map = sum(m.file_map for m in valid_file) / nf
    agg.file_success_rate = sum(m.file_any_hit for m in valid_file) / nf
    agg.file_top1_acc = sum(m.file_top1 for m in valid_file) / nf
    agg.file_top3_acc = sum(m.file_top3 for m in valid_file) / nf
    agg.file_top5_acc = sum(m.file_top5 for m in valid_file) / nf
    # Strict Acc@k — all GT files in top-k
    agg.file_strict_acc1 = sum(m.file_strict_acc1 for m in valid_file) / nf
    agg.file_strict_acc3 = sum(m.file_strict_acc3 for m in valid_file) / nf
    agg.file_strict_acc5 = sum(m.file_strict_acc5 for m in valid_file) / nf
    agg.file_strict_acc10 = sum(m.file_strict_acc10 for m in valid_file) / nf

    agg.func_precision = sum(m.func_precision for m in valid_func) / ng
    agg.func_recall = sum(m.func_recall for m in valid_func) / ng
    agg.func_f1 = sum(m.func_f1 for m in valid_func) / ng
    agg.func_mrr = sum(m.func_mrr for m in valid_func) / ng
    agg.func_ndcg = sum(m.func_ndcg for m in valid_func) / ng
    agg.func_map = sum(m.func_map for m in valid_func) / ng
    agg.func_success_rate = sum(m.func_any_hit for m in valid_func) / ng
    agg.func_top1_acc = sum(m.func_top1 for m in valid_func) / ng
    agg.func_top3_acc = sum(m.func_top3 for m in valid_func) / ng
    agg.func_top5_acc = sum(m.func_top5 for m in valid_func) / ng
    # Strict Acc@k — all GT functions in top-k
    agg.func_strict_acc5 = sum(m.func_strict_acc5 for m in valid_func) / ng
    agg.func_strict_acc10 = sum(m.func_strict_acc10 for m in valid_func) / ng

    # Module-level
    agg.module_acc1 = sum(m.module_acc1 for m in valid_func) / ng
    agg.module_acc3 = sum(m.module_acc3 for m in valid_func) / ng
    agg.module_acc5 = sum(m.module_acc5 for m in valid_func) / ng
    agg.module_acc10 = sum(m.module_acc10 for m in valid_func) / ng

    for m in cve_metrics_list:
        agg.per_cve.append({
            "cve_id": m.cve_id,
            "file_f1": round(m.file_f1, 4),
            "func_f1": round(m.func_f1, 4),
            "file_mrr": round(m.file_mrr, 4),
            "func_mrr": round(m.func_mrr, 4),
            "file_ndcg": round(m.file_ndcg, 4),
            "func_ndcg": round(m.func_ndcg, 4),
            "file_top1": m.file_top1,
            "func_top1": m.func_top1,
            "file_strict_acc1": m.file_strict_acc1,
            "file_strict_acc3": m.file_strict_acc3,
            "file_strict_acc5": m.file_strict_acc5,
            "file_strict_acc10": m.file_strict_acc10,
            "func_strict_acc5": m.func_strict_acc5,
            "func_strict_acc10": m.func_strict_acc10,
            "module_acc1": m.module_acc1,
            "module_acc3": m.module_acc3,
            "module_acc5": m.module_acc5,
            "module_acc10": m.module_acc10,
            "matched_files": m.matched_files,
            "matched_funcs": m.matched_funcs,
            "gt_files": m.gt_files,
            "gt_funcs": m.gt_funcs,
        })
    return agg


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_evaluation(
    manifest_path: str = MANIFEST_PATH,
    results_dir: str = OUTPUT_DIR,
    output_dir: str = OUTPUT_DIR,
    top_k_files: int = 15,
    top_k_funcs: int = 15,
    file_boost: float = 0.0,
) -> dict:
    """Full evaluation: load manifest, extract GT, load predictions, compute metrics.

    file_boost: if > 0, re-rank functions by combining func score with parent file score.
                combined = (1-boost)*func_score + boost*file_score
    """
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    all_metrics: List[CveMetrics] = []
    skipped_no_pred = 0
    skipped_no_gt = 0

    total = len(manifest)
    print(f"{'='*70}")
    print(f"  EVALUATION — {total} CVEs")
    print(f"  Results dir: {results_dir}")
    print(f"  GT dir: {GT_DIR}")
    if file_boost > 0:
        print(f"  File Boost:  {file_boost} (func_score × (1-{file_boost}) + file_score × {file_boost})")
    print(f"{'='*70}")

    for idx, cve in enumerate(manifest, 1):
        cve_id = cve["cve_id"]

        # Load predictions
        predictions = load_predictions(results_dir, cve_id)
        if predictions is None:
            skipped_no_pred += 1
            continue

        # Apply file-boosted re-ranking of functions (evaluation only, no data mutation)
        if file_boost > 0:
            predictions = apply_file_boost(predictions, file_boost)

        # Load GT and filter out non-code files
        gt_raw = load_gt(cve_id)
        if gt_raw is None:
            skipped_no_gt += 1
            continue
        gt = filter_gt(gt_raw)

        # Compute metrics
        metrics = compute_metrics(predictions, gt, top_k_files, top_k_funcs)
        all_metrics.append(metrics)

        hit = "HIT" if metrics.file_any_hit else "MISS"
        print(
            f"  [{idx:3d}/{total}] {cve_id:16s} | "
            f"[{hit:4s}] File MRR={metrics.file_mrr:.3f} | "
            f"Func MRR={metrics.func_mrr:.3f}"
        )

    agg = compute_aggregate(all_metrics)

    # Print
    print(f"\n{'='*70}")
    print(f"  AGGREGATE RESULTS")
    print(f"{'='*70}")
    print(f"  Total CVEs:         {total}")
    print(f"  Evaluated:          {agg.evaluated}")
    print(f"  Skipped (no pred):  {skipped_no_pred}")
    print(f"  Skipped (no GT):    {skipped_no_gt}")
    print()
    print(f"  {'='*20} File-Level {'='*20}")
    print(f"  {'':20s} {'Success':>8s} {'MRR':>8s} {'F1':>8s} {'NDCG':>8s} {'Acc@1':>8s} {'Acc@3':>8s} {'Acc@5':>8s} {'Acc@10':>8s}")
    print(f"  {'Relaxed (any hit)':20s} {agg.file_success_rate:8.4f} {agg.file_mrr:8.4f} {agg.file_f1:8.4f} {agg.file_ndcg:8.4f} {agg.file_top1_acc:8.4f} {agg.file_top3_acc:8.4f} {agg.file_top5_acc:8.4f} {'-':>8s}")
    print(f"  {'Strict (all GT in k)':20s} {'-':>8s} {'-':>8s} {'-':>8s} {'-':>8s} {agg.file_strict_acc1:8.4f} {agg.file_strict_acc3:8.4f} {agg.file_strict_acc5:8.4f} {agg.file_strict_acc10:8.4f}")
    print()
    print(f"  {'='*20} Function-Level {'='*20}")
    print(f"  {'':20s} {'Success':>8s} {'MRR':>8s} {'F1':>8s} {'NDCG':>8s} {'Acc@5':>8s} {'Acc@10':>8s}")
    print(f"  {'Relaxed (any hit)':20s} {agg.func_success_rate:8.4f} {agg.func_mrr:8.4f} {agg.func_f1:8.4f} {agg.func_ndcg:8.4f} {agg.func_top5_acc:8.4f} {'-':>8s}")
    print(f"  {'Strict (all GT in k)':20s} {'-':>8s} {'-':>8s} {'-':>8s} {'-':>8s} {agg.func_strict_acc5:8.4f} {agg.func_strict_acc10:8.4f}")
    print()
    print(f"  {'='*20} Module-Level {'='*20}")
    print(f"  {'':20s} {'Acc@1':>8s} {'Acc@3':>8s} {'Acc@5':>8s} {'Acc@10':>8s}")
    print(f"  {'Relaxed (any in class)':20s} {agg.module_acc1:8.4f} {agg.module_acc3:8.4f} {agg.module_acc5:8.4f} {agg.module_acc10:8.4f}")

    # Save
    os.makedirs(output_dir, exist_ok=True)
    agg_dict = {
        "total_cves": agg.total_cves,
        "evaluated": agg.evaluated,
        "skipped_no_pred": skipped_no_pred,
        "skipped_no_gt": skipped_no_gt,
        "file_level": {
            "success_rate": round(agg.file_success_rate, 4),
            "precision": round(agg.file_precision, 4),
            "recall": round(agg.file_recall, 4),
            "f1": round(agg.file_f1, 4),
            "mrr": round(agg.file_mrr, 4),
            "ndcg": round(agg.file_ndcg, 4),
            "map": round(agg.file_map, 4),
            "top1_accuracy": round(agg.file_top1_acc, 4),
            "top3_accuracy": round(agg.file_top3_acc, 4),
            "top5_accuracy": round(agg.file_top5_acc, 4),
            "strict_acc1": round(agg.file_strict_acc1, 4),
            "strict_acc3": round(agg.file_strict_acc3, 4),
            "strict_acc5": round(agg.file_strict_acc5, 4),
            "strict_acc10": round(agg.file_strict_acc10, 4),
        },
        "function_level": {
            "success_rate": round(agg.func_success_rate, 4),
            "precision": round(agg.func_precision, 4),
            "recall": round(agg.func_recall, 4),
            "f1": round(agg.func_f1, 4),
            "mrr": round(agg.func_mrr, 4),
            "ndcg": round(agg.func_ndcg, 4),
            "map": round(agg.func_map, 4),
            "top1_accuracy": round(agg.func_top1_acc, 4),
            "top3_accuracy": round(agg.func_top3_acc, 4),
            "top5_accuracy": round(agg.func_top5_acc, 4),
            "strict_acc5": round(agg.func_strict_acc5, 4),
            "strict_acc10": round(agg.func_strict_acc10, 4),
        },
        "module_level": {
            "acc1": round(agg.module_acc1, 4),
            "acc3": round(agg.module_acc3, 4),
            "acc5": round(agg.module_acc5, 4),
            "acc10": round(agg.module_acc10, 4),
        },
        "per_cve": agg.per_cve,
    }
    agg_path = os.path.join(output_dir, "evaluation_summary.json")
    with open(agg_path, "w", encoding="utf-8") as f:
        json.dump(agg_dict, f, indent=2, ensure_ascii=False)
    print(f"\n  Evaluation summary saved to: {agg_path}")

    detail_path = os.path.join(output_dir, "evaluation_details.json")
    detail_list = []
    for m in all_metrics:
        detail_list.append({
            "cve_id": m.cve_id,
            "file_metrics": {
                "precision": round(m.file_precision, 4),
                "recall": round(m.file_recall, 4),
                "f1": round(m.file_f1, 4),
                "mrr": round(m.file_mrr, 4),
                "ndcg": round(m.file_ndcg, 4),
                "map": round(m.file_map, 4),
                "top1": m.file_top1, "top3": m.file_top3, "top5": m.file_top5,
                "strict_acc1": m.file_strict_acc1,
                "strict_acc3": m.file_strict_acc3,
                "strict_acc5": m.file_strict_acc5,
                "strict_acc10": m.file_strict_acc10,
                "first_rank": m.file_first_rank,
            },
            "function_metrics": {
                "precision": round(m.func_precision, 4),
                "recall": round(m.func_recall, 4),
                "f1": round(m.func_f1, 4),
                "mrr": round(m.func_mrr, 4),
                "ndcg": round(m.func_ndcg, 4),
                "map": round(m.func_map, 4),
                "top1": m.func_top1, "top3": m.func_top3, "top5": m.func_top5,
                "strict_acc5": m.func_strict_acc5,
                "strict_acc10": m.func_strict_acc10,
                "first_rank": m.func_first_rank,
            },
            "module_metrics": {
                "acc1": m.module_acc1,
                "acc3": m.module_acc3,
                "acc5": m.module_acc5,
                "acc10": m.module_acc10,
            },
            "counts": {
                "gt_files": m.gt_files, "gt_funcs": m.gt_funcs,
                "pred_files": m.pred_files, "pred_funcs": m.pred_funcs,
                "matched_files": m.matched_files, "matched_funcs": m.matched_funcs,
            },
        })
    with open(detail_path, "w", encoding="utf-8") as f:
        json.dump(detail_list, f, indent=2, ensure_ascii=False)
    print(f"  Detailed metrics saved to: {detail_path}")

    return agg_dict


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Evaluate vulnerability localization predictions"
    )
    parser.add_argument("--manifest", default=MANIFEST_PATH)
    parser.add_argument("--results", default=OUTPUT_DIR)
    parser.add_argument("--output", default=OUTPUT_DIR)
    parser.add_argument("--top-k-files", type=int, default=15)
    parser.add_argument("--top-k-funcs", type=int, default=15)
    parser.add_argument("--file-boost", type=float, default=0.0,
                        help="Re-rank functions by combining func score with parent file score. "
                             "combined = (1-boost)*func_score + boost*file_score. "
                             "0.0 = original ranking, 0.5 = equal weight, 1.0 = file-only.")

    args = parser.parse_args()

    run_evaluation(
        manifest_path=args.manifest,
        results_dir=args.results,
        output_dir=args.output,
        top_k_files=args.top_k_files,
        top_k_funcs=args.top_k_funcs,
        file_boost=args.file_boost,
    )
