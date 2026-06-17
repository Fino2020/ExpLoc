"""Pre-build all graphs in parallel using multiprocessing. One-time run."""
import os, sys, time
import torch
import pandas as pd
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from config import *
from data_loader import merge_datasets


def _build_one(args):
    """Build single graph (worker function, must be picklable)."""
    idx, row_id, code, vul = args
    from graph_builder import build_pyg_graph
    data = build_pyg_graph(row_id, code)
    if data is not None:
        data.y = torch.tensor([int(vul)], dtype=torch.long)
    return idx, data


def prebuild_graphs(df, split_name, split_val, num_workers=8):
    """Build graphs for one split in parallel."""
    subset = df[df["split"] == split_val].reset_index(drop=True)
    cache_path = os.path.join(GRAPH_DIR, f"graphs_{len(subset)}.pt")

    if os.path.exists(cache_path):
        print(f"  [{split_name}] Cache exists: {cache_path}, loading to verify...")
        graphs = torch.load(cache_path, weights_only=False)
        print(f"  [{split_name}] Loaded {len(graphs)} graphs from cache")
        return

    print(f"  [{split_name}] Building {len(subset)} graphs with {num_workers} workers...")
    tasks = [
        (i, row["id"], row["func_before"], row["vul"])
        for i, (_, row) in enumerate(subset.iterrows())
    ]

    graphs = [None] * len(tasks)
    t0 = time.time()
    done = 0

    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = {pool.submit(_build_one, task): task[0] for task in tasks}
        for future in as_completed(futures):
            idx, data = future.result()
            graphs[idx] = data
            done += 1
            if done % 2000 == 0:
                elapsed = time.time() - t0
                rate = done / elapsed
                eta = (len(tasks) - done) / rate if rate > 0 else 0
                print(f"    [{split_name}] {done}/{len(tasks)} ({done/len(tasks)*100:.1f}%) "
                      f"rate={rate:.0f}/s ETA={eta:.0f}s", flush=True)

    # Remove None (failed graphs)
    graphs = [g for g in graphs if g is not None]
    torch.save(graphs, cache_path)
    elapsed = time.time() - t0
    print(f"    [{split_name}] Saved {len(graphs)} graphs to {cache_path} ({elapsed:.0f}s)")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--sample", type=int, default=0, help="Sample N for quick test")
    args = parser.parse_args()

    os.makedirs(GRAPH_DIR, exist_ok=True)
    print(f"Graph dir: {GRAPH_DIR}")

    # Load merged dataset
    print("Loading dataset...")
    df = merge_datasets(dedup=True)
    if args.sample > 0:
        df = df.sample(args.sample, random_state=42)
        from sklearn.model_selection import train_test_split
        ids = df["id"].unique()
        train_ids, test_ids = train_test_split(ids, test_size=0.2, random_state=42)
        val_ids, test_ids = train_test_split(test_ids, test_size=0.5, random_state=42)
        split_map = {}
        for i in train_ids: split_map[i] = 0
        for i in val_ids: split_map[i] = 1
        for i in test_ids: split_map[i] = 2
        df["split"] = df["id"].map(split_map).fillna(0).astype(int)

    print(f"Dataset: {len(df)} samples ({df.vul.sum()} vul)")
    for s_name, s_val in [("train", 0), ("val", 1), ("test", 2)]:
        sub = df[df["split"] == s_val]
        print(f"  {s_name}: {len(sub)} samples ({sub.vul.sum()} vul)")

    # Prebuild all three splits in parallel
    for s_name, s_val in [("train", 0), ("val", 1), ("test", 2)]:
        prebuild_graphs(df, s_name, s_val, num_workers=args.workers)

    print("\nDone. All graph caches built.")


if __name__ == "__main__":
    main()
