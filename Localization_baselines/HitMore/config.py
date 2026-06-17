"""
HitMore adaptation for VulnLocalization — configuration.
GPU: PyTorch MLP (CUDA 11.8, RTX 3070 Ti)
"""

import os

# Paths
PROJECT_ROOT = "/mnt/d/Desktop/VulnLocalization"
MANIFEST_PATH = os.path.join(PROJECT_ROOT, "Dataset", "processing_dataset", "full_manifest.json")
GT_DIR = os.path.join(PROJECT_ROOT, "Dataset", "GT")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "HitMore", "output")

# HitMore original data paths
HITMORE_BASE = "/mnt/d/Desktop/HitMore-main/dataset"
HITMORE_MERGE_DIR = os.path.join(HITMORE_BASE, "merge_data_without_GT")
HITMORE_BUGLOCATOR_DIR = os.path.join(HITMORE_BASE, "bugLocator")

# ML config
RANDOM_SEED = 42
N_FOLDS = 5
TEST_SIZE = 0.2

# PyTorch MLP hyperparams (GPU)
MLP_PARAMS = {
    "hidden_dims": [256, 128, 64],
    "dropout": 0.3,
    "epochs": 80,
    "batch_size": 128,
    "lr": 0.001,
    "weight_decay": 1e-4,
    "early_stop_patience": 10,
}

# Default training samples per HitMore dataset (0 = all)
DEFAULT_TRAIN_SAMPLES_PER_DATASET = 100

# Candidate generation
TOP_K_CANDIDATES = 20  # top files to consider per CVE (mimics HitMore top-20)

# Legacy sklearn RF params (used by kfold mode fallback)
RF_PARAMS = {
    "n_estimators": 100,
    "max_depth": 10,
    "max_features": 0.5,
    "max_samples": 0.7,
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
}
