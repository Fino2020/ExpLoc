#!/usr/bin/env python3
"""
HitMore adaptation for VulnLocalization — main entry point.

Modes:
  full_repo   Train MLP on HitMore → predict ALL repo files → save result.json
              Then run evaluate.py externally. This is the CORRECT baseline.
  cross_project  (legacy) Internal eval on tiny candidate pool — INFLATED metrics
  kfold       (legacy) K-fold CV on VulnLocalization only — INFLATED metrics

Usage:
  # Correct baseline (full-repo ranking)
  python3 -m HitMore.main --mode full_repo --limit 0
  # Then:
  cd Explainable_Localization
  python3 evaluate.py --manifest ../Dataset/full_manifest.json \
      --results ../HitMore/output/full_repo --output ../HitMore/output/full_repo

  # Quick test
  python3 -m HitMore.main --mode full_repo --limit 30

  # Legacy (inflated metrics — DO NOT USE for baselines)
  python3 -m HitMore.main --mode cross_project --limit 30
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from HitMore.model import (
    train_and_evaluate_cross_project,
    train_and_evaluate_kfold,
    train_and_evaluate_full_repo,
    save_results,
    print_results,
)
from HitMore.dataset import build_dataset
from HitMore.config import RF_PARAMS, N_FOLDS, OUTPUT_DIR


def main(limit=None, n_estimators=None, max_depth=None, output_dir=None,
         mode="full_repo", train_samples=0, skip_training=False):
    if n_estimators:
        RF_PARAMS["n_estimators"] = n_estimators
    if max_depth:
        RF_PARAMS["max_depth"] = max_depth
    output_dir = output_dir or OUTPUT_DIR

    import torch
    print("=" * 60)
    print("HITMORE ADAPTATION — VULNERABILITY LOCALIZATION")
    print(f"Model: PyTorch MLP (GPU: {torch.cuda.is_available()})")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"Mode: {mode}")
    if mode == "full_repo":
        print("Protocol: rank ALL files in repo → save result.json → evaluate.py")
    elif mode == "cross_project":
        print(f"Train samples/dataset: {train_samples if train_samples else 'ALL'}")
        print("WARNING: Internal eval on tiny candidate pool — INFLATED metrics")
    elif mode == "kfold":
        print("WARNING: K-fold on tiny candidate pool — INFLATED metrics")
    print("=" * 60)

    if mode == "full_repo":
        # Correct: train on HitMore, predict ALL repo files, save result.json
        train_samples_per = train_samples if train_samples > 0 else None
        cvcs, model_dir, result_dir = train_and_evaluate_full_repo(
            test_limit=limit,
            train_samples_per_dataset=train_samples_per,
            verbose=True,
            output_dir=output_dir,
            skip_training=skip_training,
        )
        return {"model_dir": model_dir, "result_dir": result_dir}

    elif mode == "cross_project":
        # Legacy: internal eval on tiny candidate pool (INFLATED)
        train_samples_per = train_samples if train_samples > 0 else 100
        agg, all_cve_metrics, fold_results, feature_importance, model_dir = \
            train_and_evaluate_cross_project(
                test_limit=limit,
                train_samples_per_dataset=train_samples_per,
                verbose=True,
                output_dir=output_dir,
            )

        save_results(agg, all_cve_metrics, fold_results, feature_importance, output_dir)
        print_results(agg)
        return agg

    elif mode == "kfold":
        # Legacy: K-fold CV on VulnLocalization data only (INFLATED)
        print("\n[1/3] Building dataset from VulnLocalization manifest + GT cache...")
        df = build_dataset(limit=limit)

        if len(df) == 0:
            print("ERROR: No data generated. Check:")
            print("  1. /mnt/d/Desktop/VulnLocalization/Dataset/full_manifest.json exists")
            print("  2. /mnt/d/Desktop/VulnLocalization/Dataset/GT/ has .json files")
            print("  3. Repo paths in manifest are valid (repos cloned)")
            sys.exit(1)

        print(f"\n[2/3] Training RandomForest with {N_FOLDS}-fold CV (grouped by CVE)...")
        agg, all_cve_metrics, fold_results, feature_importance, model_dir = \
            train_and_evaluate_kfold(df, output_dir=output_dir)

        save_results(agg, all_cve_metrics, fold_results, feature_importance, output_dir)
        print_results(agg)
        return agg

    else:
        print(f"ERROR: Unknown mode '{mode}'.")
        print("Use 'full_repo' (correct), 'cross_project', or 'kfold'.")
        sys.exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="HitMore adaptation for VulnLocalization vulnerability localization"
    )
    parser.add_argument("--mode", type=str, default="full_repo",
                        choices=["full_repo", "cross_project", "kfold"],
                        help="full_repo: rank ALL files (correct baseline) | "
                             "cross_project/kfold: legacy (inflated metrics)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max CVEs to test (0=all)")
    parser.add_argument("--n-estimators", type=int, default=RF_PARAMS["n_estimators"],
                        help=f"RandomForest n_estimators (legacy only)")
    parser.add_argument("--max-depth", type=int, default=RF_PARAMS["max_depth"],
                        help=f"RandomForest max_depth (legacy only)")
    parser.add_argument("--train-samples", type=int, default=0,
                        help="Samples per HitMore dataset for training (0=all)")
    parser.add_argument("--output", type=str, default=OUTPUT_DIR,
                        help=f"Output directory")
    parser.add_argument("--skip-train", action="store_true",
                        help="Skip training if cached model exists")
    args = parser.parse_args()

    limit = args.limit if args.limit > 0 else None
    train_samples = args.train_samples
    main(limit=limit,
         n_estimators=args.n_estimators,
         max_depth=args.max_depth,
         output_dir=args.output,
         mode=args.mode,
         train_samples=train_samples,
         skip_training=args.skip_train)
