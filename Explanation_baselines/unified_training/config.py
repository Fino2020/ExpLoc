"""Shared config for unified detector training."""
import os

# Paths
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "checkpoints")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Dataset paths (download from Google Drive first)
BIGVUL_PATH = os.path.join(DATA_DIR, "MSR_data_cleaned.csv")
DEVIGN_PATH = os.path.join(DATA_DIR, "Devign.json")
REVEAL_PATH = os.path.join(DATA_DIR, "Reveal")
ISSUE2COMMIT_PATH = "/mnt/d/Desktop/VulnLocalization/Dataset/dataset_with_changed_files_filter.json"
REPO_BASE = "/mnt/e/Desktop/Localization_Repo/Localization_Repo"

# Graph
GRAPH_DIR = os.path.join(DATA_DIR, "graphs")
MAX_NODES_PER_GRAPH = 500

# Model
HIDDEN_DIM = 128
NUM_GNN_LAYERS = 3
DROPOUT = 0.3
NUM_CLASSES = 2
POOLING = "mean"

# Training
BATCH_SIZE = 32
LEARNING_RATE = 0.001
NUM_EPOCHS = 50
EARLY_STOP_PATIENCE = 10
TRAIN_RATIO = 0.8
VAL_RATIO = 0.1
