"""
ML model training and evaluation — GPU adaptation with PyTorch.

Evaluation metrics aligned with Explainable_Localization/evaluate.py:
  - File-level:   Success Rate, MRR, Top-1/3/5, Precision, Recall, F1, NDCG@15, MAP@15
  - Function-level: same set
  - Per-CVE output: evaluation_summary.json + evaluation_details.json

GPU: PyTorch MLP binary classifier (CUDA 11.8, RTX 3070 Ti)
"""

import json
import math
import os
import time
import numpy as np
import pandas as pd
from collections import defaultdict
from sklearn.metrics import precision_recall_fscore_support
from sklearn.preprocessing import StandardScaler

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

from HitMore.config import RF_PARAMS, OUTPUT_DIR, N_FOLDS, RANDOM_SEED
from HitMore.dataset import build_dataset, prepare_features, get_kfold_splits, \
    build_full_candidates, build_result_json, extract_function_names_from_file
from HitMore.hitmore_data_loader import load_hitmore_training_data

os.makedirs(OUTPUT_DIR, exist_ok=True)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ============================================================
# PyTorch MLP Model
# ============================================================

class VulnMLP(nn.Module):
    """Simple MLP for binary vulnerability file classification."""

    def __init__(self, input_dim, hidden_dims=[256, 128, 64], dropout=0.3):
        super().__init__()
        layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            layers.extend(
                [
                    nn.Linear(prev_dim, h_dim),
                    nn.BatchNorm1d(h_dim),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                ]
            )
            prev_dim = h_dim
        layers.append(nn.Linear(prev_dim, 1))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x).squeeze(-1)


def train_pytorch_model(
        X_train, y_train, X_val=None, y_val=None,
        epochs=50, batch_size=256, lr=0.001,
        pos_weight=None, verbose=True
        ):
    """Train PyTorch MLP on GPU."""
    from tqdm import tqdm

    input_dim = X_train.shape[1]
    model = VulnMLP(input_dim).to(DEVICE)

    if pos_weight is None:
        neg_count = (y_train == 0).sum()
        pos_count = max((y_train == 1).sum(), 1)
        pos_weight_val = neg_count / pos_count
    else:
        pos_weight_val = pos_weight

    pos_weight_tensor = torch.tensor([pos_weight_val]).to(DEVICE)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight_tensor)
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)

    X_t = torch.FloatTensor(X_train).to(DEVICE)
    y_t = torch.FloatTensor(y_train).to(DEVICE)
    dataset = TensorDataset(X_t, y_t)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    if X_val is not None:
        X_v = torch.FloatTensor(X_val).to(DEVICE)
        y_v = torch.FloatTensor(y_val).to(DEVICE)

    best_loss = float("inf")
    best_state = None
    patience = 10
    patience_counter = 0

    pbar = tqdm(range(epochs), desc="Training", unit="epoch", disable=not verbose)
    for epoch in pbar:
        model.train()
        epoch_loss = 0.0
        for batch_X, batch_y in loader:
            optimizer.zero_grad()
            logits = model(batch_X)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        avg_loss = epoch_loss / len(loader)

        if X_val is not None:
            model.eval()
            with torch.no_grad():
                val_logits = model(X_v)
                val_loss = criterion(val_logits, y_v).item()
            if val_loss < best_loss:
                best_loss = val_loss
                best_state = { k: v.clone() for k, v in model.state_dict().items() }
                patience_counter = 0
            else:
                patience_counter += 1
        else:
            if avg_loss < best_loss:
                best_loss = avg_loss
                best_state = { k: v.clone() for k, v in model.state_dict().items() }
                patience_counter = 0
            else:
                patience_counter += 1

        val_str = f" val={val_loss:.4f}" if X_val is not None else ""
        pbar.set_postfix({ "loss": f"{avg_loss:.4f}{val_str}", "best": f"{best_loss:.4f}", "pat": patience_counter })

        if patience_counter >= patience:
            if verbose:
                tqdm.write(f"  Early stopping at epoch {epoch + 1}")
            break

    pbar.close()
    if best_state is not None:
        model.load_state_dict(best_state)

    return model


def predict_proba(model, X):
    """Get prediction probabilities from PyTorch model."""
    model.eval()
    X_t = torch.FloatTensor(X).to(DEVICE)
    with torch.no_grad():
        logits = model(X_t)
        probs = torch.sigmoid(logits).cpu().numpy()
    return probs


def predict(model, X):
    """Get binary predictions."""
    return (predict_proba(model, X) >= 0.5).astype(int)


# ============================================================
# Fuzzy matching (aligned with evaluate.py)
# ============================================================

def _match_files(pred_files, gt_files):
    """Match predicted file paths to ground-truth file paths.
    3-level fuzzy matching (same as evaluate.py):
      1. Exact path match (case-insensitive)
      2. Path suffix match
      3. Basename match with directory overlap
    """
    matched = set()
    gt_lower = { gf.lower(): gf for gf in gt_files }

    gt_by_basename = { }
    for gf in gt_files:
        bn = os.path.basename(gf).lower()
        gt_by_basename.setdefault(bn, set()).add(gf)

    for pf in pred_files:
        pf_lower = pf.lower()
        pf_bn = os.path.basename(pf).lower()

        if pf_lower in gt_lower:
            matched.add(gt_lower[pf_lower])
            continue

        found_l2 = False
        for gf_lower, gf in gt_lower.items():
            if pf_lower.endswith(gf_lower) or gf_lower.endswith(pf_lower):
                matched.add(gf)
                found_l2 = True
                break
        if found_l2:
            continue

        if pf_bn in gt_by_basename:
            candidates = gt_by_basename[pf_bn]
            best, best_score = None, -1
            pf_dirs = set(pf_lower.replace("\\", "/").split("/")[:-1])
            for c in candidates:
                c_dirs = set(c.lower().replace("\\", "/").split("/")[:-1])
                overlap = len(pf_dirs & c_dirs)
                if overlap > best_score:
                    best_score = overlap
                    best = c
            if best:
                matched.add(best)
            else:
                matched.update(candidates)

    return matched


def _levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(
                min(
                    prev[j] + 1,
                    curr[j - 1] + 1,
                    prev[j - 1] + (0 if ca == cb else 1),
                )
            )
        prev = curr
    return prev[-1]


def _normalize_function_name(name):
    name = name.strip().rstrip(";{}")
    if "\\" in name:
        name = name.rsplit("\\", 1)[-1]
    if "/" in name and ":" in name:
        parts = name.split(":")
        if len(parts) >= 2:
            name = parts[1]
    return name


def _match_functions(pred_funcs, gt_funcs):
    """5-level fuzzy matching (aligned with evaluate.py)."""
    matched = set()
    gt_lower = { f.lower(): f for f in gt_funcs }

    gt_short = { }
    for f in gt_funcs:
        fl = f.lower()
        norm = _normalize_function_name(fl)
        gt_short.setdefault(norm, set()).add(f)
        last = fl.rsplit("::", 1)[-1].rsplit(".", 1)[-1].rsplit("->", 1)[-1]
        if last != norm:
            gt_short.setdefault(last, set()).add(f)

    for pf in pred_funcs:
        pf_lower = _normalize_function_name(pf.lower())

        if pf_lower in gt_lower:
            matched.add(gt_lower[pf_lower])
            continue

        if pf_lower in gt_short:
            matched.update(gt_short[pf_lower])
            continue

        pf_last = pf_lower.rsplit("::", 1)[-1].rsplit(".", 1)[-1].rsplit("->", 1)[-1]
        if pf_last != pf_lower and pf_last in gt_short:
            matched.update(gt_short[pf_last])
            continue

        found_l4 = False
        for gf_lower, gf in gt_lower.items():
            gf_norm = _normalize_function_name(gf_lower)
            if pf_lower in gf_norm or gf_norm in pf_lower:
                min_len = min(len(pf_lower), len(gf_norm))
                if min_len >= 4 and (pf_lower[:3] == gf_norm[:3] or pf_lower[-3:] == gf_norm[-3:]):
                    matched.add(gf)
                    found_l4 = True
                    break
            gf_last = gf_norm.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
            if pf_last in gf_last or gf_last in pf_last:
                if len(pf_last) >= 4 or pf_last == gf_last:
                    matched.add(gf)
                    found_l4 = True
                    break
        if found_l4:
            continue

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
            if best_match is not None:
                matched.add(best_match)

    return matched


# ============================================================
# NDCG & MAP (aligned with evaluate.py)
# ============================================================

def _compute_dcg(relevance, k):
    dcg = 0.0
    for i in range(min(k, len(relevance))):
        rel = relevance[i]
        if rel > 0:
            dcg += rel / (math.log2(i + 2))
    return dcg


def _compute_ndcg(pred_list, gt_set, match_fn, k=15):
    if not gt_set:
        return 0.0
    relevance = []
    for pred in pred_list[:k]:
        matched = match_fn([pred], gt_set)
        relevance.append(1 if matched else 0)
    ideal_rel = sorted(relevance, reverse=True)
    dcg = _compute_dcg(relevance, k)
    idcg = _compute_dcg(ideal_rel, k)
    if idcg == 0:
        return 0.0
    return dcg / idcg


def _compute_map(pred_list, gt_set, match_fn, k=15):
    if not gt_set:
        return 0.0
    num_hits = 0
    sum_precisions = 0.0
    for i, pred in enumerate(pred_list[:k]):
        matched = match_fn([pred], gt_set)
        if matched:
            num_hits += 1
            sum_precisions += num_hits / (i + 1)
    if num_hits == 0:
        return 0.0
    return sum_precisions / min(len(gt_set), k)


# ============================================================
# Per-CVE metrics (matching evaluate.py CveMetrics)
# ============================================================

def compute_cve_metrics(
        cve_id, pred_files, gt_files, pred_funcs, gt_funcs,
        top_k_files=15, top_k_funcs=15
        ):
    m = {
        "cve_id":     cve_id,
        "gt_files":   len(gt_files),
        "gt_funcs":   len(gt_funcs),
        "pred_files": len(pred_files[:top_k_files]),
        "pred_funcs": len(pred_funcs[:top_k_funcs]),
    }

    pred_files_k = pred_files[:top_k_files]
    pred_funcs_k = pred_funcs[:top_k_funcs]

    # File-level
    matched_files = _match_files(pred_files_k, gt_files)
    m["matched_files"] = len(matched_files)
    m["file_any_hit"] = 1 if len(matched_files) > 0 else 0
    m["file_precision"] = len(matched_files) / len(pred_files_k) if len(pred_files_k) > 0 else 0.0
    m["file_recall"] = len(matched_files) / len(gt_files) if len(gt_files) > 0 else 0.0
    fp, fr = m["file_precision"], m["file_recall"]
    m["file_f1"] = 2 * fp * fr / (fp + fr) if (fp + fr) > 0 else 0.0

    m["file_mrr"] = 0.0
    m["file_first_rank"] = -1
    m["file_top1"] = m["file_top3"] = m["file_top5"] = 0
    for rank, pf in enumerate(pred_files_k, 1):
        matched = _match_files([pf], gt_files)
        if matched:
            m["file_mrr"] = 1.0 / rank
            m["file_first_rank"] = rank
            break
    if m["file_first_rank"] > 0:
        if m["file_first_rank"] <= 1:
            m["file_top1"] = 1
        if m["file_first_rank"] <= 3:
            m["file_top3"] = 1
        if m["file_first_rank"] <= 5:
            m["file_top5"] = 1

    m["file_ndcg"] = _compute_ndcg(pred_files_k, gt_files, _match_files, k=15)
    m["file_map"] = _compute_map(pred_files_k, gt_files, _match_files, k=15)

    # Function-level
    if gt_funcs:
        matched_funcs = _match_functions(pred_funcs_k, gt_funcs)
        m["matched_funcs"] = len(matched_funcs)
        m["func_any_hit"] = 1 if len(matched_funcs) > 0 else 0
        m["func_precision"] = len(matched_funcs) / len(pred_funcs_k) if len(pred_funcs_k) > 0 else 0.0
        m["func_recall"] = len(matched_funcs) / len(gt_funcs) if len(gt_funcs) > 0 else 0.0
        fp, fr = m["func_precision"], m["func_recall"]
        m["func_f1"] = 2 * fp * fr / (fp + fr) if (fp + fr) > 0 else 0.0

        m["func_mrr"] = 0.0
        m["func_first_rank"] = -1
        m["func_top1"] = m["func_top3"] = m["func_top5"] = 0
        for rank, pf in enumerate(pred_funcs_k, 1):
            matched = _match_functions([pf], gt_funcs)
            if matched:
                m["func_mrr"] = 1.0 / rank
                m["func_first_rank"] = rank
                break
        if m["func_first_rank"] > 0:
            if m["func_first_rank"] <= 1:
                m["func_top1"] = 1
            if m["func_first_rank"] <= 3:
                m["func_top3"] = 1
            if m["func_first_rank"] <= 5:
                m["func_top5"] = 1

        m["func_ndcg"] = _compute_ndcg(pred_funcs_k, gt_funcs, _match_functions, k=15)
        m["func_map"] = _compute_map(pred_funcs_k, gt_funcs, _match_functions, k=15)
    else:
        m.update({ f"func_{k}": 0.0 for k in ["any_hit", "precision", "recall", "f1", "mrr", "ndcg", "map"] })
        m["func_first_rank"] = -1
        m["func_top1"] = m["func_top3"] = m["func_top5"] = 0
        m["matched_funcs"] = 0

    return m


# ============================================================
# Aggregate metrics (matching evaluate.py AggregateMetrics)
# ============================================================

def compute_aggregate(per_cve_metrics):
    valid_file = [m for m in per_cve_metrics if m["gt_files"] > 0]
    valid_func = [m for m in per_cve_metrics if m["gt_funcs"] > 0]
    nf = max(len(valid_file), 1)
    ng = max(len(valid_func), 1)

    agg = {
        "total_cves": len(per_cve_metrics),
        "evaluated":  sum(1 for m in per_cve_metrics if m["gt_files"] > 0 or m["gt_funcs"] > 0),
    }

    agg["file_level"] = {
        "success_rate":  round(sum(m["file_any_hit"] for m in valid_file) / nf, 4),
        "precision":     round(sum(m["file_precision"] for m in valid_file) / nf, 4),
        "recall":        round(sum(m["file_recall"] for m in valid_file) / nf, 4),
        "f1":            round(sum(m["file_f1"] for m in valid_file) / nf, 4),
        "mrr":           round(sum(m["file_mrr"] for m in valid_file) / nf, 4),
        "ndcg":          round(sum(m["file_ndcg"] for m in valid_file) / nf, 4),
        "map":           round(sum(m["file_map"] for m in valid_file) / nf, 4),
        "top1_accuracy": round(sum(m["file_top1"] for m in valid_file) / nf, 4),
        "top3_accuracy": round(sum(m["file_top3"] for m in valid_file) / nf, 4),
        "top5_accuracy": round(sum(m["file_top5"] for m in valid_file) / nf, 4),
    }

    file_ranks = [m["file_first_rank"] for m in valid_file if m["file_first_rank"] > 0]
    agg["file_level"]["avg_first_rank"] = round(sum(file_ranks) / len(file_ranks), 1) if file_ranks else -1.0

    agg["function_level"] = {
        "success_rate":  round(sum(m["func_any_hit"] for m in valid_func) / ng, 4),
        "precision":     round(sum(m["func_precision"] for m in valid_func) / ng, 4),
        "recall":        round(sum(m["func_recall"] for m in valid_func) / ng, 4),
        "f1":            round(sum(m["func_f1"] for m in valid_func) / ng, 4),
        "mrr":           round(sum(m["func_mrr"] for m in valid_func) / ng, 4),
        "ndcg":          round(sum(m["func_ndcg"] for m in valid_func) / ng, 4),
        "map":           round(sum(m["func_map"] for m in valid_func) / ng, 4),
        "top1_accuracy": round(sum(m["func_top1"] for m in valid_func) / ng, 4),
        "top3_accuracy": round(sum(m["func_top3"] for m in valid_func) / ng, 4),
        "top5_accuracy": round(sum(m["func_top5"] for m in valid_func) / ng, 4),
    }

    func_ranks = [m["func_first_rank"] for m in valid_func if m["func_first_rank"] > 0]
    agg["function_level"]["avg_first_rank"] = round(sum(func_ranks) / len(func_ranks), 1) if func_ranks else -1.0

    agg["counts"] = {
        "with_file_gt":  len(valid_file),
        "with_func_gt":  len(valid_func),
        "skipped_no_gt": agg["total_cves"] - agg["evaluated"],
    }

    return agg


# ============================================================
# Cross-project transfer: train on HitMore (GPU), test on VulnLocalization
# ============================================================

def train_and_evaluate_cross_project(
        test_limit=None, train_samples_per_dataset=100,
        verbose=True, output_dir=OUTPUT_DIR
        ):
    """Train PyTorch MLP on HitMore data, evaluate on VulnLocalization CVEs.

    Args:
        test_limit: max CVEs to evaluate (None = all)
        train_samples_per_dataset: samples per HitMore dataset (6 datasets total)
        verbose: print progress
        output_dir: where to save model + results
    """
    # [1] Load HitMore training data (sampled)
    if verbose:
        print("\n" + "=" * 60)
        print("[1/5] Loading HitMore training data (sampled, GPU mode)...")
        print(f"  Device: {DEVICE}")
        print("=" * 60)

    train_df = load_hitmore_training_data(
        max_neg_ratio=3, verbose=verbose,
        dedup_test_files=True
        )

    # Sample per dataset (stratified by label)
    if train_samples_per_dataset and "_dataset" in train_df.columns:
        sampled_dfs = []
        for ds_name, group in train_df.groupby("_dataset"):
            n = min(train_samples_per_dataset, len(group))
            # Stratified sampling: sample each class proportionally
            pos = group[group["label"] == 1]
            neg = group[group["label"] == 0]
            n_pos = max(1, int(n * len(pos) / len(group)))
            n_neg = n - n_pos
            n_pos = min(n_pos, len(pos))
            n_neg = min(n_neg, len(neg))
            sampled_pos = pos.sample(n=n_pos, random_state=RANDOM_SEED) if n_pos > 0 else pd.DataFrame()
            sampled_neg = neg.sample(n=n_neg, random_state=RANDOM_SEED) if n_neg > 0 else pd.DataFrame()
            sampled_dfs.append(pd.concat([sampled_pos, sampled_neg]))
        train_df = pd.concat(sampled_dfs, ignore_index=True)
        if verbose:
            pos = train_df["label"].sum()
            print(f"\n  Sampled training: {len(train_df)} rows ({pos} pos, {len(train_df) - pos} neg)")

    # [2] Load VulnLocalization test data
    if verbose:
        print("\n" + "=" * 60)
        print("[2/5] Building VulnLocalization test set...")
        print("=" * 60)

    test_df = build_dataset(limit=test_limit, verbose=verbose)

    if verbose:
        print(
            f"\n  Test set: {len(test_df)} rows, "
            f"Pos: {test_df['label'].sum()}, Neg: {(test_df['label'] == 0).sum()}"
            )

    # [3] Prepare features
    if verbose:
        print("\n" + "=" * 60)
        print("[3/5] Preparing features (GPU tensors)...")
        print("=" * 60)

    for drop_c in ["_dataset", "_source"]:
        if drop_c in train_df.columns:
            train_df = train_df.drop(columns=[drop_c])

    X_train, y_train, feature_names, scaler = prepare_features(train_df)
    X_test, y_test, test_fn, _ = prepare_features(test_df)

    # Align columns
    train_set = set(feature_names)
    test_feat_df = pd.DataFrame(X_test, columns=test_fn)
    missing_in_test = train_set - set(test_fn)
    extra_in_test = set(test_fn) - train_set

    if verbose:
        print(f"  Train features: {len(feature_names)}, Test features: {len(test_fn)}")
        if missing_in_test:
            print(f"  Adding to test (zeros): {len(missing_in_test)}")
        if extra_in_test:
            print(f"  Dropping from test: {len(extra_in_test)}")

    for col in missing_in_test:
        test_feat_df[col] = 0.0
    test_feat_df = test_feat_df[feature_names]
    X_test = test_feat_df.values

    if verbose:
        print(f"  Train: {X_train.shape}, Test: {X_test.shape}")

    # [4] Train PyTorch MLP on GPU
    if verbose:
        print("\n" + "=" * 60)
        print("[4/5] Training PyTorch MLP on GPU...")
        print(f"  Device: {DEVICE}")
        print("=" * 60)

    # Split 10% of training for validation
    from sklearn.model_selection import train_test_split
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.1, random_state=RANDOM_SEED, stratify=y_train
    )

    pos_count = max((y_tr == 1).sum(), 1)
    neg_count = max((y_tr == 0).sum(), 1)
    pos_weight = neg_count / pos_count
    if verbose:
        print(
            f"  Train: {len(X_tr)} (pos={pos_count}, neg={neg_count}), "
            f"Val: {len(X_val)}, pos_weight={pos_weight:.2f}"
            )

    t0 = time.time()
    model = train_pytorch_model(
        X_tr, y_tr, X_val, y_val,
        epochs=80, batch_size=128, lr=0.001,
        pos_weight=pos_weight, verbose=verbose,
    )
    train_time = time.time() - t0
    if verbose:
        print(f"  Training completed in {train_time:.1f}s")

    # [5] Evaluate on VulnLocalization test set
    if verbose:
        print("\n" + "=" * 60)
        print("[5/5] Evaluating on VulnLocalization test set...")
        print("=" * 60)

    y_proba = predict_proba(model, X_test)
    test_df = test_df.copy()
    test_df["y_proba"] = y_proba

    all_cve_metrics = []
    for cve_id, group in test_df.groupby("cve_id"):
        ranked = group.sort_values("y_proba", ascending=False)
        pred_files = ranked["file_path"].tolist()
        gt_files = set(group[group["label"] == 1]["file_path"].tolist())

        gt_funcs = set()
        if "_gt_funcs" in group.columns:
            try:
                gt_funcs_raw = group["_gt_funcs"].iloc[0]
                if isinstance(gt_funcs_raw, str):
                    gt_funcs = set(json.loads(gt_funcs_raw))
            except (json.JSONDecodeError, KeyError, IndexError):
                pass

        pred_funcs = [os.path.splitext(os.path.basename(fp))[0] for fp in pred_files]
        metrics = compute_cve_metrics(cve_id, pred_files, gt_files, pred_funcs[:15], gt_funcs)
        all_cve_metrics.append(metrics)

    agg = compute_aggregate(all_cve_metrics)

    y_pred = predict(model, X_test)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
    acc = (y_pred == y_test).mean()

    fold_results = [{
        "fold":              0,
        "note":              "cross-project: train=HitMore(GPU-MLP), test=VulnLocalization",
        "accuracy":          float(acc),
        "precision":         float(prec),
        "recall":            float(rec),
        "f1":                float(f1),
        "file_success_rate": agg["file_level"]["success_rate"],
        "train_time":        train_time,
        "n_test_cves":       len(all_cve_metrics),
    }]

    if verbose:
        print(f"  Binary: Acc={acc:.4f} Prec={prec:.4f} Rec={rec:.4f} F1={f1:.4f}")

    # Feature importance via permutation (simple approximation)
    feature_importance = { }
    # Use the scaler's feature_names_placeholder for now
    for i, fn in enumerate(feature_names):
        feature_importance[fn] = 1.0 / len(feature_names)  # placeholder

    # Save model
    model_dir = os.path.join(output_dir, "model")
    os.makedirs(model_dir, exist_ok=True)

    model_path = os.path.join(model_dir, "hitmore_mlp_gpu.pt")
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "input_dim":        X_train.shape[1],
            "feature_names":    list(feature_names),
        }, model_path
    )

    # Save scaler + metadata
    import joblib
    scaler_path = os.path.join(model_dir, "scaler.pkl")
    joblib.dump(scaler, scaler_path)

    meta_path = os.path.join(model_dir, "feature_names.json")
    with open(meta_path, "w") as f:
        json.dump({ "feature_names": list(feature_names) }, f)

    if verbose:
        print(f"\n  Model saved: {model_path}")
        print(f"  Scaler saved: {scaler_path}")

    return agg, all_cve_metrics, fold_results, feature_importance, model_dir


# ============================================================
# K-fold CV on VulnLocalization only (GPU)
# ============================================================

def train_and_evaluate_kfold(df, verbose=True, output_dir=OUTPUT_DIR):
    """Train PyTorch MLP in K-fold CV, evaluate per evaluate.py metrics."""
    all_cve_metrics = []
    fold_results = []

    folds = list(get_kfold_splits(df, n_folds=N_FOLDS))

    for fold_idx, (train_df, test_df) in enumerate(folds):
        if verbose:
            print(f"\n--- Fold {fold_idx + 1}/{N_FOLDS} ---")
            print(f"  Train: {len(train_df)} rows, Test: {len(test_df)} rows")

        X_train, y_train, feature_names, scaler = prepare_features(train_df)
        X_test, y_test, _, _ = prepare_features(test_df)

        # Align
        test_feat_df = pd.DataFrame(X_test, columns=feature_names)
        X_test = test_feat_df[feature_names].values

        t0 = time.time()
        model = train_pytorch_model(X_train, y_train, epochs=50, batch_size=128, verbose=False)
        train_time = time.time() - t0

        y_proba = predict_proba(model, X_test)
        test_df = test_df.copy()
        test_df["y_proba"] = y_proba

        cve_metrics_fold = []
        for cve_id, group in test_df.groupby("cve_id"):
            ranked = group.sort_values("y_proba", ascending=False)
            pred_files = ranked["file_path"].tolist()
            gt_files = set(group[group["label"] == 1]["file_path"].tolist())

            gt_funcs = set()
            if "_gt_funcs" in group.columns:
                try:
                    gt_funcs_raw = group["_gt_funcs"].iloc[0]
                    if isinstance(gt_funcs_raw, str):
                        gt_funcs = set(json.loads(gt_funcs_raw))
                except (json.JSONDecodeError, KeyError, IndexError):
                    pass

            pred_funcs = [os.path.splitext(os.path.basename(fp))[0] for fp in pred_files]
            metrics = compute_cve_metrics(cve_id, pred_files, gt_files, pred_funcs[:15], gt_funcs)
            cve_metrics_fold.append(metrics)

        all_cve_metrics.extend(cve_metrics_fold)

        y_pred = predict(model, X_test)
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
        acc = (y_pred == y_test).mean()

        fold_file_sr = sum(m["file_any_hit"] for m in cve_metrics_fold if m["gt_files"] > 0)
        fold_file_n = max(sum(1 for m in cve_metrics_fold if m["gt_files"] > 0), 1)

        fold_results.append(
            {
                "fold":              fold_idx,
                "accuracy":          float(acc), "precision": float(prec), "recall": float(rec), "f1": float(f1),
                "file_success_rate": float(fold_file_sr / fold_file_n),
                "train_time":        train_time, "n_cves": len(cve_metrics_fold),
            }
        )

        if verbose:
            print(
                f"  Acc={acc:.4f} Prec={prec:.4f} Rec={rec:.4f} F1={f1:.4f} "
                f"FileSR={fold_file_sr / fold_file_n:.4f} CVEs={len(cve_metrics_fold)} Time={train_time:.1f}s"
                )

    agg = compute_aggregate(all_cve_metrics)

    # Train final model on all data
    if verbose:
        print(f"\n--- Training final model on all {len(df)} samples ---")
    X_all, y_all, feature_names, all_scaler = prepare_features(df)
    final_model = train_pytorch_model(X_all, y_all, epochs=50, batch_size=128, verbose=False)

    model_dir = os.path.join(output_dir, "model")
    os.makedirs(model_dir, exist_ok=True)
    torch.save(
        {
            "model_state_dict": final_model.state_dict(),
            "input_dim":        X_all.shape[1],
            "feature_names":    list(feature_names),
        }, os.path.join(model_dir, "hitmore_mlp_gpu.pt")
    )

    feature_importance = { fn: 1.0 / len(feature_names) for fn in feature_names }

    return agg, all_cve_metrics, fold_results, feature_importance, model_dir


# ============================================================
# Output (matching evaluate.py output format)
# ============================================================

def save_results(agg, all_cve_metrics, fold_results, feature_importance, output_dir=OUTPUT_DIR):
    summary = {
        "total_cves":     agg["total_cves"],
        "evaluated":      agg["evaluated"],
        "file_level":     agg["file_level"],
        "function_level": agg["function_level"],
        "counts":         agg["counts"],
        "fold_results":   fold_results,
        "top_features":   sorted(
            [{ "feature": k, "importance": float(v) } for k, v in feature_importance.items()],
            key=lambda x: x["importance"], reverse=True
        )[:20],
    }

    summary_path = os.path.join(output_dir, "evaluation_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\nEvaluation summary saved to: {summary_path}")

    detail_list = []
    for m in all_cve_metrics:
        detail_list.append(
            {
                "cve_id":           m["cve_id"],
                "file_metrics":     {
                    "precision":  round(m["file_precision"], 4), "recall": round(m["file_recall"], 4),
                    "f1":         round(m["file_f1"], 4), "mrr": round(m["file_mrr"], 4),
                    "ndcg":       round(m["file_ndcg"], 4), "map": round(m["file_map"], 4),
                    "top1":       m["file_top1"], "top3": m["file_top3"], "top5": m["file_top5"],
                    "first_rank": m["file_first_rank"],
                },
                "function_metrics": {
                    "precision":  round(m["func_precision"], 4), "recall": round(m["func_recall"], 4),
                    "f1":         round(m["func_f1"], 4), "mrr": round(m["func_mrr"], 4),
                    "ndcg":       round(m["func_ndcg"], 4), "map": round(m["func_map"], 4),
                    "top1":       m["func_top1"], "top3": m["func_top3"], "top5": m["func_top5"],
                    "first_rank": m["func_first_rank"],
                },
                "counts":           {
                    "gt_files":      m["gt_files"], "gt_funcs": m["gt_funcs"],
                    "pred_files":    m["pred_files"], "pred_funcs": m["pred_funcs"],
                    "matched_files": m["matched_files"], "matched_funcs": m.get("matched_funcs", 0),
                },
            }
        )

    detail_path = os.path.join(output_dir, "evaluation_details.json")
    with open(detail_path, "w") as f:
        json.dump(detail_list, f, indent=2, ensure_ascii=False)
    print(f"Detailed metrics saved to: {detail_path}")
    return summary


def print_results(agg):
    fl = agg["file_level"]
    fnl = agg["function_level"]
    print(f"\n{'=' * 70}")
    print(f"  AGGREGATE RESULTS")
    print(f"{'=' * 70}")
    print(f"  Total CVEs evaluated:      {agg['total_cves']}")
    print(f"  With file GT:              {agg['counts']['with_file_gt']}")
    print(f"  With function GT:          {agg['counts']['with_func_gt']}")
    print()
    print(
        f"  {'':20s} {'Success':>8s} {'MRR':>8s} {'Top-1':>8s} {'Top-3':>8s} {'Top-5':>8s} {'F1(ref)':>8s} {'NDCG':>8s}"
        )
    print(
        f"  {'File-level':20s} {fl['success_rate']:8.4f} {fl['mrr']:8.4f} {fl['top1_accuracy']:8.4f} {fl['top3_accuracy']:8.4f} {fl['top5_accuracy']:8.4f} {fl['f1']:8.4f} {fl['ndcg']:8.4f}"
        )
    print(
        f"  {'Function-level':20s} {fnl['success_rate']:8.4f} {fnl['mrr']:8.4f} {fnl['top1_accuracy']:8.4f} {fnl['top3_accuracy']:8.4f} {fnl['top5_accuracy']:8.4f} {fnl['f1']:8.4f} {fnl['ndcg']:8.4f}"
        )
    print(f"\n{'=' * 70}")
    print(f"  ADDITIONAL METRICS")
    print(f"{'=' * 70}")
    print(f"  File MAP@15:    {fl['map']:.4f}")
    print(f"  File Avg Rank:  {fl.get('avg_first_rank', 'N/A')}")
    print(f"  Func MAP@15:    {fnl['map']:.4f}")
    print(f"  Func Avg Rank:  {fnl.get('avg_first_rank', 'N/A')}")
    print(f"{'=' * 70}")


# ============================================================
# Full-Repo Evaluation (correct protocol — rank ALL files)
# ============================================================

def predict_full_repo(
        model, scaler, feature_names, cvcs, batch_size=256,
        verbose=True
        ):
    """Score ALL files in each CVE's repo using the trained MLP.

    Args:
        model: trained VulnMLP
        scaler: fitted StandardScaler
        feature_names: ordered list of training feature names
        cvcs: list from build_full_candidates()
        batch_size: GPU inference batch size

    Returns:
        cvcs updated with 'ranked_files' and 'ranked_funcs'
    """
    import pandas as pd

    for cve_idx, cve in enumerate(cvcs):
        files = cve["files"]
        if not files:
            cve["ranked_files"] = []
            cve["ranked_funcs"] = []
            continue

        paths = [fp for fp, _ in files]
        feat_dicts = [fd for _, fd in files]

        # Build feature matrix
        feat_df = pd.DataFrame(feat_dicts)

        # Align with training features
        for col in set(feature_names) - set(feat_df.columns):
            feat_df[col] = 0.0
        extra = set(feat_df.columns) - set(feature_names)
        if extra:
            feat_df = feat_df.drop(columns=list(extra))
        feat_df = feat_df[feature_names]
        feat_df = feat_df.fillna(0)

        X = feat_df.values.astype(np.float32)
        X_scaled = scaler.transform(X)

        # Score in batches
        probs = predict_proba(model, X_scaled)

        # Rank by probability descending
        ranked = sorted(
            zip(paths, probs.tolist()),
            key=lambda x: x[1], reverse=True
            )

        cve["ranked_files"] = ranked
        cve["ranked_funcs"] = []  # filled later by extract_functions_posthoc

        if verbose and (cve_idx + 1) % 50 == 0:
            n_files = len(ranked)
            gt_hit = "N/A"
            if cve.get("gt_files"):
                top1 = ranked[0][0] if ranked else ""
                gt_hit = "HIT" if top1 in cve["gt_files"] else "MISS"
            print(
                f"  [{cve_idx + 1}/{len(cvcs)}] {cve['cve_id']}: "
                f"{n_files} files ranked, top-1={gt_hit}"
                )

    return cvcs


def extract_functions_posthoc(result_dir, top_n=50, verbose=True):
    """Post-processing: read saved result.jsons, extract functions from top files.

    Called AFTER scoring + saving to avoid blocking the main pipeline with
    slow file I/O from the external repo drive. Updates result.json in-place.
    """
    import glob

    # Load manifest for repo_path lookup
    from HitMore.config import MANIFEST_PATH
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    repo_map = { }
    for entry in manifest:
        cid = entry.get("cve_id", "")
        if cid:
            repo_map[cid] = entry.get("repo_path", "")

    pattern = os.path.join(result_dir, "CVE-*", "result.json")
    result_files = sorted(glob.glob(pattern))
    if not result_files:
        if verbose:
            print("  No result.json files found for function extraction")
        return 0

    updated = 0
    for rf in result_files:
        try:
            with open(rf, "r", encoding="utf-8") as f:
                result = json.load(f)

            cve_id = result.get("cve_id", "")
            ranked_files = result.get("pipeline", { }).get("_ranked_files", [])
            if not ranked_files:
                continue

            repo_path = repo_map.get(cve_id, "")
            if not repo_path or not os.path.isdir(repo_path):
                continue

            func_names = set()
            for fp, _ in ranked_files[:top_n]:
                content = None
                if repo_path:
                    full_path = os.path.join(repo_path, fp)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                    except Exception:
                        pass
                if content:
                    fns = extract_function_names_from_file(fp, content)
                    for fn in fns:
                        if fn not in func_names:
                            func_names.add(fn)
                        if len(func_names) >= 100:
                            break
                if len(func_names) >= 100:
                    break

            # Update ranked_functions
            result["pipeline"]["_ranked_functions"] = [
                [fn, 1.0] for fn in list(func_names)[:100]
            ]

            with open(rf, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            updated += 1

            if verbose and updated % 100 == 0:
                print(f"  Function extraction: {updated}/{len(result_files)}")
        except Exception:
            continue

    if verbose:
        print(f"  Function extraction complete: {updated}/{len(result_files)} updated")
    return updated


def save_result_jsons(cvcs, output_dir):
    """Save VulnLocalization-compatible result.json per CVE."""
    os.makedirs(output_dir, exist_ok=True)
    saved = 0
    for cve in cvcs:
        cve_dir = os.path.join(output_dir, cve["cve_id"])
        os.makedirs(cve_dir, exist_ok=True)
        result = build_result_json(
            cve,
            cve.get("ranked_files", []),
            cve.get("ranked_funcs", []),
        )
        out_path = os.path.join(cve_dir, "result.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        saved += 1
    print(f"\nSaved {saved} result.json files to {output_dir}")
    return saved


def train_and_evaluate_full_repo(
        test_limit=None, train_samples_per_dataset=None,
        verbose=True, output_dir=OUTPUT_DIR,
        skip_training=False
        ):
    """Full pipeline: train MLP on HitMore, predict ALL repo files, save result.json.

    This is the CORRECT evaluation protocol — every file in the repo is ranked,
    matching the conditions used by VulnLocalization's evaluate.py.

    After this finishes, run:
        cd Explainable_Localization
        python3 evaluate.py --manifest ../Dataset/dataset_with_changed_files_filter.json \
            --results ../HitMore/output/full_repo --output ../HitMore/output/full_repo
    """
    import joblib

    model_dir = os.path.join(output_dir, "model")
    model_path = os.path.join(model_dir, "hitmore_mlp_gpu.pt")
    scaler_path = os.path.join(model_dir, "scaler.pkl")

    # Check for cached model
    if skip_training and os.path.exists(model_path) and os.path.exists(scaler_path):
        if verbose:
            print("\n" + "=" * 60)
            print("[SKIP] Loading cached model — training skipped")
            print(f"  Model: {model_path}")
            print(f"  Scaler: {scaler_path}")
            print("=" * 60)

        ckpt = torch.load(model_path, map_location=DEVICE)
        feature_names = ckpt["feature_names"]
        model = VulnMLP(ckpt["input_dim"]).to(DEVICE)
        model.load_state_dict(ckpt["model_state_dict"])
        model.eval()
        scaler = joblib.load(scaler_path)
        train_time = 0.0
    else:
        # [1-2] Train model
        if verbose:
            print("\n" + "=" * 60)
            print("[1/4] Loading HitMore training data...")
            print(f"  Device: {DEVICE}")
            print("=" * 60)

        train_df = load_hitmore_training_data(
            max_neg_ratio=3, verbose=verbose,
            dedup_test_files=True
            )

        if train_samples_per_dataset and "_dataset" in train_df.columns:
            sampled_dfs = []
            for ds_name, group in train_df.groupby("_dataset"):
                n = min(train_samples_per_dataset, len(group))
                pos = group[group["label"] == 1]
                neg = group[group["label"] == 0]
                n_pos = max(1, int(n * len(pos) / len(group)))
                n_neg = n - n_pos
                n_pos = min(n_pos, len(pos))
                n_neg = min(n_neg, len(neg))
                sampled_pos = pos.sample(n=n_pos, random_state=RANDOM_SEED) if n_pos > 0 else pd.DataFrame()
                sampled_neg = neg.sample(n=n_neg, random_state=RANDOM_SEED) if n_neg > 0 else pd.DataFrame()
                sampled_dfs.append(pd.concat([sampled_pos, sampled_neg]))
            train_df = pd.concat(sampled_dfs, ignore_index=True)

        for drop_c in ["_dataset", "_source"]:
            if drop_c in train_df.columns:
                train_df = train_df.drop(columns=[drop_c])

        if verbose:
            print(f"\n[2/4] Preparing features + training MLP...")
        X_train, y_train, feature_names, scaler = prepare_features(train_df)

        from sklearn.model_selection import train_test_split
        X_tr, X_val, y_tr, y_val = train_test_split(
            X_train, y_train, test_size=0.1, random_state=RANDOM_SEED, stratify=y_train
        )

        pos_count = max((y_tr == 1).sum(), 1)
        neg_count = max((y_tr == 0).sum(), 1)
        pos_weight = neg_count / pos_count

        t0 = time.time()
        model = train_pytorch_model(
            X_tr, y_tr, X_val, y_val,
            epochs=80, batch_size=128, lr=0.001,
            pos_weight=pos_weight, verbose=verbose,
        )
        train_time = time.time() - t0
        if verbose:
            print(f"  Training: {train_time:.1f}s | model={sum(p.numel() for p in model.parameters()):,} params")

        # Save model
        os.makedirs(model_dir, exist_ok=True)
        torch.save(
            {
                "model_state_dict": model.state_dict(),
                "input_dim":        X_train.shape[1],
                "feature_names":    list(feature_names),
            }, model_path
        )
        joblib.dump(scaler, scaler_path)

    # [3] Build full-repo candidates
    if verbose:
        print(f"\n[3/4] Building full-repo candidates (ALL files, NO sampling)...")

    cvcs = build_full_candidates(limit=test_limit, source_only=True, verbose=verbose)

    if verbose:
        total_files = sum(len(c["files"]) for c in cvcs)
        print(f"  Total: {len(cvcs)} CVEs, {total_files} files to score")

    # [4] Score all files + save result.json
    if verbose:
        print(f"\n[4/4] Scoring ALL files per CVE...")

    cvcs = predict_full_repo(model, scaler, feature_names, cvcs, verbose=verbose)

    result_dir = os.path.join(output_dir, "full_repo")
    saved = save_result_jsons(cvcs, result_dir)

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"  Full-repo predictions saved to: {result_dir}")

    # [5] Post-hoc function extraction (deferred to avoid I/O bottleneck)
    if verbose:
        print(f"\n[5/5] Extracting functions from top-ranked files (tree-sitter)...")
    extract_functions_posthoc(result_dir, verbose=verbose)

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"  Full pipeline complete.")
        print(f"  To evaluate, run:")
        print(f"    cd Explainable_Localization")
        print(f"    python3 evaluate.py --manifest ../Dataset/dataset_with_changed_files_filter.json \\")
        print(f"        --results ../HitMore/output/full_repo \\")
        print(f"        --output ../HitMore/output/full_repo")
        print(f"{'=' * 60}")

    return cvcs, model_dir, result_dir


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--output", type=str, default=OUTPUT_DIR)
    parser.add_argument(
        "--mode", type=str, default="kfold",
        choices=["kfold", "cross_project"],
        help="kfold: internal CV (flawed), cross_project: train HitMore→test VulnLocalization (flawed)"
        )
    args = parser.parse_args()

    limit = args.limit if args.limit > 0 else None

    print("=" * 60)
    print("HITMORE GPU ADAPTATION — PyTorch MLP")
    print(f"Device: {DEVICE}")
    print("=" * 60)

    print("\n[1/3] Building dataset...")
    df = build_dataset(limit=limit)
    if len(df) == 0:
        print("ERROR: No data.");
        exit(1)

    print(f"\n[2/3] Training & evaluating ({N_FOLDS}-fold CV, GPU)...")
    agg, all_cve_metrics, fold_results, feature_importance = train_and_evaluate_kfold(df)

    print(f"\n[3/3] Saving results...")
    save_results(agg, all_cve_metrics, fold_results, feature_importance, args.output)
    print_results(agg)
