"""
Evaluate baseline results with standard File/Function/Module Acc@k metrics.
Treats missing predictions as wrong (not skipped) by default.

Usage:
  python3 -m acr_baseline.evaluate_acr --results ../Results/ACR
  python3 -m acr_baseline.evaluate_acr --results ../Results/Agentless --count-missing
"""

import json
import os
import sys
from argparse import ArgumentParser

_LOC_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT_DIR = os.path.dirname(_LOC_DIR)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

from evaluate import (
    load_predictions, compute_metrics, compute_aggregate,
    Predictions,
)
from shared.config import MANIFEST_PATH, GT_DIR
from shared.gt_loader import load_gt, filter_gt


def run_evaluation_strict(
    manifest_path: str = MANIFEST_PATH,
    results_dir: str = "",
    output_dir: str = "",
    top_k_files: int = 10,
    top_k_funcs: int = 60,
    file_boost: float = 0.0,
    count_missing: bool = True,
) -> dict:
    """Full evaluation with option to count missing predictions as wrong."""

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    all_metrics: list = []
    skipped_no_pred = 0
    skipped_no_gt = 0
    missing_counted_as_wrong = 0

    total = len(manifest)
    print(f"{'='*70}")
    print(f"  EVALUATION — {total} CVEs")
    print(f"  Results dir: {results_dir}")
    print(f"  GT dir: {GT_DIR}")
    print(f"  Count missing as wrong: {count_missing}")
    print(f"{'='*70}")

    for idx, cve in enumerate(manifest, 1):
        cve_id = cve["cve_id"]

        predictions = load_predictions(results_dir, cve_id)
        if predictions is None:
            if count_missing:
                # Create empty prediction — counts as wrong
                predictions = Predictions(cve_id=cve_id)
                missing_counted_as_wrong += 1
            else:
                skipped_no_pred += 1
                continue

        if file_boost > 0:
            predictions = apply_file_boost(predictions, file_boost)

        gt_raw = load_gt(cve_id)
        if gt_raw is None:
            skipped_no_gt += 1
            continue
        gt = filter_gt(gt_raw)

        metrics = compute_metrics(predictions, gt, top_k_files, top_k_funcs)
        all_metrics.append(metrics)

        hit = "HIT" if metrics.file_any_hit else "MISS"
        print(
            f"  [{idx:3d}/{total}] {cve_id:16s} | "
            f"[{hit:4s}] File MRR={metrics.file_mrr:.3f} | "
            f"Func MRR={metrics.func_mrr:.3f}"
        )

    agg = compute_aggregate(all_metrics)

    print(f"\n{'='*70}")
    print(f"  AGGREGATE RESULTS")
    print(f"{'='*70}")
    print(f"  Total CVEs:         {total}")
    print(f"  Evaluated:          {agg.evaluated}")
    if not count_missing:
        print(f"  Skipped (no pred):  {skipped_no_pred}")
    else:
        print(f"  Missing→wrong:      {missing_counted_as_wrong}")
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

    os.makedirs(output_dir, exist_ok=True)
    summary = {
        "total_cves": agg.total_cves,
        "evaluated": agg.evaluated,
        "skipped_no_pred": skipped_no_pred,
        "skipped_no_gt": skipped_no_gt,
        "missing_counted_as_wrong": missing_counted_as_wrong,
        "count_missing": count_missing,
        "file_level": {
            "success_rate": round(agg.file_success_rate, 4),
            "mrr": round(agg.file_mrr, 4),
            "f1": round(agg.file_f1, 4),
            "strict_acc1": round(agg.file_strict_acc1, 4),
            "strict_acc3": round(agg.file_strict_acc3, 4),
            "strict_acc5": round(agg.file_strict_acc5, 4),
            "strict_acc10": round(agg.file_strict_acc10, 4),
        },
        "function_level": {
            "success_rate": round(agg.func_success_rate, 4),
            "mrr": round(agg.func_mrr, 4),
            "f1": round(agg.func_f1, 4),
            "strict_acc5": round(agg.func_strict_acc5, 4),
            "strict_acc10": round(agg.func_strict_acc10, 4),
        },
        "module_level": {
            "acc1": round(agg.module_acc1, 4),
            "acc3": round(agg.module_acc3, 4),
            "acc5": round(agg.module_acc5, 4),
            "acc10": round(agg.module_acc10, 4),
        },
    }
    with open(os.path.join(output_dir, "evaluation_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    return summary


if __name__ == "__main__":
    parser = ArgumentParser(description="Evaluate Baseline Results")
    parser.add_argument("--results", type=str, default="../Results/ACR")
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--manifest", type=str, default=MANIFEST_PATH)
    parser.add_argument("--top-k-files", type=int, default=10)
    parser.add_argument("--top-k-funcs", type=int, default=60)
    parser.add_argument("--file-boost", type=float, default=0.0)
    parser.add_argument("--count-missing", action="store_true", default=True,
                        help="Count CVEs with no result.json as wrong (not skipped)")

    args = parser.parse_args()
    results_dir = os.path.abspath(args.results)
    output_dir = os.path.abspath(args.output or args.results)

    from evaluate import apply_file_boost

    run_evaluation_strict(
        manifest_path=args.manifest,
        results_dir=results_dir,
        output_dir=output_dir,
        top_k_files=args.top_k_files,
        top_k_funcs=args.top_k_funcs,
        file_boost=args.file_boost,
        count_missing=args.count_missing,
    )
