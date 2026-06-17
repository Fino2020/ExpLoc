"""Unified data loader: BigVul + Devign + Reveal, dedup against Issue2Commit.

Real formats:
  BigVul:  MSR_data_cleaned.csv (func_before, vul, CVE ID, lang, ...)
  Devign:  Devign.json (list of {project, commit_id, target, func})
  Reveal:  Reveal/vulnerables.json + Reveal/non-vulnerables.json
"""
import json, os, pickle, re
import pandas as pd
import numpy as np
import torch
from torch_geometric.data import Data, Dataset
from sklearn.model_selection import train_test_split
from config import *

def load_bigvul():
    """Load BigVul dataset. Uses Parquet cache for speed."""
    if not os.path.exists(BIGVUL_PATH):
        print(f"  BigVul not found at {BIGVUL_PATH}")
        return _empty_df()

    pkl_path = os.path.join(DATA_DIR, "bigvul_minimal.pkl")
    if os.path.exists(pkl_path):
        print(f"  BigVul: loading from cache {pkl_path}")
        df = pd.read_pickle(pkl_path)
        print(f"  BigVul: {len(df)} samples ({df.vul.sum()} vulnerable)")
        return _clean_cols(df)

    print("  BigVul: CSV -> Pickle (one-time, ~15 min)...", flush=True)
    import csv as _csv
    _csv.field_size_limit(2**27)
    cols = ["func_before", "vul", "CVE ID", "lang", "file_name", "commit_id"]
    chunks = []
    for i, ch in enumerate(pd.read_csv(BIGVUL_PATH, usecols=cols, chunksize=50000, engine='python')):
        chunks.append(ch.copy())
        if (i+1) % 40 == 0:
            print(f"    {i*50000:,} rows...", flush=True)
    df = pd.concat(chunks, ignore_index=True)
    df = df[df["func_before"].notna() & (df["func_before"].str.len() > 20)]
    df["id"] = range(len(df))
    df["dataset"] = "bigvul"
    df["cve_id"] = df.get("CVE ID", "")
    df["func_after"] = ""
    df["vul"] = df["vul"].fillna(0).astype(int)
    df = _clean_cols(df)
    df.to_pickle(pkl_path)
    print(f"  BigVul: cached to {pkl_path}")
    df["id"] = range(len(df))
    df["dataset"] = "bigvul"
    df["cve_id"] = df.get("CVE ID", "")
    df["func_after"] = ""  # not needed for detection
    if "vul" not in df.columns:
        df["vul"] = 0
    df["vul"] = df["vul"].fillna(0).astype(int)
    # Filter: need non-empty func_before
    df = df[df["func_before"].notna() & (df["func_before"].str.len() > 20)]
    print(f"  BigVul: {len(df)} samples ({df.vul.sum()} vulnerable)")
    return _clean_cols(df)

def load_devign():
    """Load Devign dataset."""
    if not os.path.exists(DEVIGN_PATH):
        print(f"  Devign not found at {DEVIGN_PATH}")
        return _empty_df()
    data = json.load(open(DEVIGN_PATH))
    rows = []
    for i, item in enumerate(data):
        rows.append({
            "id": f"devign_{i}",
            "func_before": item.get("func", ""),
            "func_after": "",
            "vul": int(item.get("target", 0)),
            "dataset": "devign",
            "cve_id": "",
            "lang": "",
            "project": item.get("project", "unknown"),
        })
    df = pd.DataFrame(rows)
    df = df[df["func_before"].str.len() > 20]
    print(f"  Devign: {len(df)} samples ({df.vul.sum()} vulnerable)")
    return _clean_cols(df)

def load_reveal():
    """Load Reveal dataset."""
    reveal_dir = REVEAL_PATH
    if not os.path.isdir(reveal_dir):
        reveal_dir = os.path.join(DATA_DIR, "Reveal")
    vul_path = os.path.join(reveal_dir, "vulnerables.json")
    nv_path = os.path.join(reveal_dir, "non-vulnerables.json")
    if not os.path.exists(vul_path):
        print(f"  Reveal not found at {reveal_dir}")
        return _empty_df()

    rows = []
    for path, label in [(vul_path, 1), (nv_path, 0)]:
        if not os.path.exists(path):
            continue
        data = json.load(open(path))
        for i, item in enumerate(data):
            code = item.get("code", item.get("func", ""))
            rows.append({
                "id": f"reveal_{label}_{i}",
                "func_before": code,
                "func_after": "",
                "vul": label,
                "dataset": "reveal",
                "cve_id": "",
                "lang": "",
                "project": item.get("project", "unknown"),
            })
    df = pd.DataFrame(rows)
    df = df[df["func_before"].str.len() > 20]
    print(f"  Reveal: {len(df)} samples ({df.vul.sum()} vulnerable)")
    return _clean_cols(df)

def _empty_df():
    return pd.DataFrame(columns=["id", "func_before", "func_after", "vul", "dataset", "cve_id", "lang", "project"])

def _clean_cols(df):
    """Ensure standard columns."""
    for col, default in [("id", "unknown"), ("func_before", ""), ("func_after", ""),
                           ("vul", 0), ("dataset", "unknown"), ("cve_id", ""),
                           ("lang", ""), ("project", "unknown")]:
        if col not in df.columns:
            df[col] = default
    return df[["id", "func_before", "func_after", "vul", "dataset", "cve_id", "lang", "project"]]

def load_issue2commit_cves():
    """Extract CVE IDs from Issue2Commit for dedup."""
    if not os.path.exists(ISSUE2COMMIT_PATH):
        return set()
    with open(ISSUE2COMMIT_PATH) as f:
        data = json.load(f)
    cves = set()
    for entry in data:
        cve = entry.get("cve_id", "")
        if cve and cve.startswith("CVE-"):
            cves.add(cve)
    return cves

def merge_datasets(dedup=True, balance=True):
    """Merge BigVul + Devign + Reveal, dedup vs Issue2Commit."""
    dfs = [load_bigvul(), load_devign(), load_reveal()]
    df = pd.concat([d for d in dfs if len(d) > 0], ignore_index=True)
    print(f"  Merged: {len(df)} samples ({df.vul.sum()} vulnerable)")

    if dedup:
        i2c_cves = load_issue2commit_cves()
        if i2c_cves:
            before = len(df)
            # Remove samples whose CVE overlaps with Issue2Commit
            mask = df["cve_id"].apply(lambda c: str(c) not in i2c_cves)
            df = df[mask]
            removed = before - len(df)
            print(f"  After dedup vs Issue2Commit ({len(i2c_cves)} CVEs): {len(df)} samples (removed {removed})")

    if balance and df.vul.sum() > 0:
        # Balance: equal vul/non-vul samples
        vul = df[df.vul == 1]
        nv = df[df.vul == 0]
        n_keep = min(len(vul), len(nv))
        if n_keep < len(nv):
            nv = nv.sample(n_keep, random_state=42)
        df = pd.concat([vul, nv], ignore_index=True)
        print(f"  After balancing: {len(df)} samples ({df.vul.sum()} vul, {len(df)-df.vul.sum()} non-vul)")

    # Train/val/test split
    train_ids, test_ids = train_test_split(df["id"].unique(), test_size=0.2, random_state=42)
    val_ids, test_ids = train_test_split(test_ids, test_size=0.5, random_state=42)
    id_to_split = {}
    for i in train_ids: id_to_split[i] = 0
    for i in val_ids: id_to_split[i] = 1
    for i in test_ids: id_to_split[i] = 2
    df["split"] = df["id"].map(id_to_split)
    df["split"] = df["split"].fillna(0).astype(int)

    return df

class UnifiedGraphDataset(Dataset):
    """PyG Dataset with caching."""
    def __init__(self, df, split="train", transform=None, pre_transform=None):
        self.split_name = split
        self.df = df[df["split"] == {"train": 0, "val": 1, "test": 2}[split]].reset_index(drop=True)
        os.makedirs(GRAPH_DIR, exist_ok=True)
        super().__init__(GRAPH_DIR, transform, pre_transform)
        self._cache = None

    @property
    def processed_dir(self): return GRAPH_DIR
    @property
    def processed_file_names(self): return [f"graphs_{self.split_name}_{len(self.df)}.pt"]

    def _load_graphs(self):
        if self._cache is not None:
            return self._cache
        cache_path = os.path.join(GRAPH_DIR, f"graphs_{self.split_name}_{len(self.df)}.pt")
        if os.path.exists(cache_path):
            self._cache = torch.load(cache_path, weights_only=False)
            return self._cache

        ckpt_path = os.path.join(GRAPH_DIR, f"graphs_{self.split_name}_{len(self.df)}_ckpt.pt")
        from graph_builder import build_pyg_graph
        graphs = []
        start_idx = 0

        # Resume from checkpoint if it exists
        if os.path.exists(ckpt_path):
            ckpt = torch.load(ckpt_path, weights_only=False)
            graphs = ckpt["graphs"]
            start_idx = ckpt["last_idx"]
            print(f"  Resuming graph building from idx {start_idx}/{len(self.df)} ({len(graphs)} valid graphs)", flush=True)

        rows = list(self.df.iterrows())
        for i in range(start_idx, len(rows)):
            _, row = rows[i]
            data = build_pyg_graph(row["id"], row["func_before"])
            if data is not None:
                data.y = torch.tensor([int(row["vul"])], dtype=torch.long)
                graphs.append(data)
            if (i + 1) % 2000 == 0 and i > start_idx:
                torch.save({"graphs": graphs, "last_idx": i + 1}, ckpt_path)
                print(f"  Graph building: {i+1}/{len(self.df)} (ckpt saved, {len(graphs)} valid)", flush=True)

        torch.save(graphs, cache_path)
        if os.path.exists(ckpt_path):
            os.remove(ckpt_path)
        self._cache = graphs
        return graphs

    def len(self): return len(self._load_graphs())
    def get(self, idx): return self._load_graphs()[idx]

if __name__ == "__main__":
    df = merge_datasets(dedup=True, balance=True)
    print(f"\nFinal: {len(df)} samples")
    print(f"  Vul: {df.vul.sum()}, Non-vul: {len(df)-df.vul.sum()}")
    print(f"  Split: train={len(df[df.split==0])}, val={len(df[df.split==1])}, test={len(df[df.split==2])}")
    os.makedirs(DATA_DIR, exist_ok=True)
    df.to_csv(os.path.join(DATA_DIR, "merged_dataset.csv"), index=False)
    print(f"  Saved to merged_dataset.csv")
