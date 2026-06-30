"""
Shared configuration — loads paths and LLM settings from .env.
"""
import os
from dotenv import load_dotenv

_ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
if os.path.exists(_ENV_PATH):
    load_dotenv(_ENV_PATH)
else:
    load_dotenv()

PROJECT_ROOT = os.getenv("PROJECT_ROOT", os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Data paths
MANIFEST_PATH = os.getenv("MANIFEST_PATH", os.path.join(PROJECT_ROOT, "Dataset/dataset_with_changed_files_filter.json"))
DATASET_PATH = os.getenv("DATASET_PATH", os.path.join(PROJECT_ROOT, "Dataset/dataset_with_changed_files_filter.json"))
KG_DIR = os.getenv("KG_DIR", os.path.join(PROJECT_ROOT, "KG_Construction/Graphs"))
HISTORY_DIR = os.path.join(PROJECT_ROOT, "KG_Construction/history/history")
ICFG_DIR = os.getenv("ICFG_DIR", os.path.join(PROJECT_ROOT, "Static_Analysis/Results/CodeQL"))
SCUBA_RESULTS_DIR = os.getenv("SCUBA_RESULTS_DIR", os.path.join(PROJECT_ROOT, "Static_Analysis/Results/ScubaTrace"))
GT_DIR = os.path.join(PROJECT_ROOT, "Dataset/GT")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", os.path.join(PROJECT_ROOT, "Results/Localization/Localization"))
REPO_BASE = os.getenv("REPO_BASE", "")
RMS_DB_DIR = os.path.join(PROJECT_ROOT, "Localization/rms_db")

# LLM settings — primary: OPENAI_DS_API_KEY
OPENAI_DS_API_KEY = os.getenv("OPENAI_DS_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "deepseek-v4-flash")
OPENAI_MODEL_V4PRO = os.getenv("OPENAI_MODEL_V4PRO", os.getenv("OPENAI_MODE_V4PRO", "deepseek-v4-pro"))

XIANYU_API_KEY = os.getenv("XIANYU_API_KEY", "")
XIANYU_BASE_URL = os.getenv("XIANYU_BASE_URL", "")
XIANYU_MODEL = os.getenv("XIANYU_MODEL", "deepseek-v4-flash")
XIANYU_MODEL_V4PRO = os.getenv("XIANYU_MODEL_V4PRO", "deepseek-v4-pro")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
DEEPSEEK_MODEL_PRO = os.getenv("DEEPSEEK_MODEL_PRO", "deepseek-v4-pro")
