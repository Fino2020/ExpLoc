"""
Build Repo Memory Store (RMS) from git commit history.

Implements the RepoMem paper (ICLR 2026):
  - Episodic Memory: BM25-indexed commit corpus (§3.1)
  - Semantic Memory: LLM-generated file functionality summaries (§3.2)

Schema:
  commits(sha, message, author, date, linked_issues, patch, modified_files)
  file_hotspots(file_path, edit_count, last_modified, functionality_summary)
  meta(key, value) — BM25 params, repo info

Usage:
  python3 build_rms.py <repo_path> <output_db> [--max-commits 500] [--top-hotspots 30]
"""

import json
import os
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
ISSUE_REF_PATTERN = re.compile(
    r'(?:fix|close|resolve|address)(?:es|ed|s)?\s+#(\d+)', re.IGNORECASE
)
GITHUB_ISSUE_PATTERN = re.compile(
    r'(?:github\.com/[\w.-]+/[\w.-]+/issues/)(\d+)', re.IGNORECASE
)


# ---------------------------------------------------------------------------
# BM25 Index
# ---------------------------------------------------------------------------

class BM25Index:
    """BM25 ranking function over commit messages.

    Parameters match the paper: k1=1.2, b=0.75.
    """

    def __init__(self, k1: float = 1.2, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.docs: Dict[str, str] = {}          # sha -> message
        self.doc_freq: Dict[str, int] = defaultdict(int)
        self.term_freqs: Dict[str, Dict[str, int]] = {}
        self.doc_lengths: Dict[str, int] = {}
        self.avg_dl = 0.0
        self.N = 0

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r'[a-z0-9]{2,}', text.lower())

    def add(self, doc_id: str, text: str):
        tokens = self._tokenize(text)
        self.docs[doc_id] = text
        self.doc_lengths[doc_id] = len(tokens)
        tf: Dict[str, int] = defaultdict(int)
        for t in tokens:
            tf[t] += 1
        self.term_freqs[doc_id] = dict(tf)
        for t in set(tokens):
            self.doc_freq[t] += 1
        self.N += 1
        self.avg_dl = sum(self.doc_lengths.values()) / max(self.N, 1)

    def search(self, query: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """Return top-k (doc_id, score) matches."""
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        scores: Dict[str, float] = defaultdict(float)
        for token in set(query_tokens):
            df = self.doc_freq.get(token, 0)
            if df == 0:
                continue
            idf = self._idf(df)
            for doc_id in self.docs:
                tf = self.term_freqs.get(doc_id, {}).get(token, 0)
                if tf == 0:
                    continue
                dl = self.doc_lengths[doc_id]
                numerator = tf * (self.k1 + 1)
                denominator = tf + self.k1 * (1 - self.b + self.b * dl / self.avg_dl)
                scores[doc_id] += idf * numerator / denominator

        return sorted(scores.items(), key=lambda x: -x[1])[:top_k]

    def _idf(self, df: int) -> float:
        import math
        return math.log((self.N - df + 0.5) / (df + 0.5) + 1.0)

    def to_dict(self) -> dict:
        return {
            "k1": self.k1, "b": self.b, "N": self.N, "avg_dl": self.avg_dl,
            "doc_freq": dict(self.doc_freq),
            "doc_lengths": self.doc_lengths,
            "term_freqs": self.term_freqs,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BM25Index":
        idx = cls(k1=d["k1"], b=d["b"])
        idx.N = d["N"]
        idx.avg_dl = d["avg_dl"]
        idx.doc_freq = defaultdict(int, d["doc_freq"])
        idx.doc_lengths = d["doc_lengths"]
        idx.term_freqs = d["term_freqs"]
        idx.docs = {}  # messages not serialized; reload from DB
        return idx


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _run_git(repo_path: str, args: List[str], timeout: int = 60) -> str:
    """Run a git command and return stdout."""
    result = subprocess.run(
        ["git", "-C", repo_path] + args,
        capture_output=True, text=True, timeout=timeout,
    )
    return result.stdout


def _get_commit_list(repo_path: str, max_commits: int = 500) -> List[dict]:
    """Return list of commit dicts from git log."""
    output = _run_git(
        repo_path,
        ["log", "--all", "--pretty=format:%H|%s|%an|%aI", f"-n{max_commits}"],
        timeout=120,
    )
    commits = []
    for line in output.strip().split("\n"):
        if not line:
            continue
        parts = line.split("|", 3)
        if len(parts) >= 4:
            commits.append({
                "sha": parts[0],
                "message": parts[1],
                "author": parts[2],
                "date": parts[3],
            })
    return commits


def _get_commit_patch(repo_path: str, sha: str) -> str:
    """Return unified diff for a commit."""
    return _run_git(repo_path, ["diff-tree", "--no-commit-id", "-p", sha], timeout=30)


def _get_changed_files(repo_path: str, sha: str) -> List[str]:
    """Return list of files changed in a commit."""
    output = _run_git(
        repo_path, ["diff-tree", "--no-commit-id", "--name-only", "-r", sha], timeout=30
    )
    return [f.strip() for f in output.split("\n") if f.strip()]


def _extract_linked_issues(message: str) -> str:
    """Extract CVE IDs and issue references from a commit message."""
    issues: set = set()
    for m in CVE_PATTERN.finditer(message):
        issues.add(m.group(0).upper())
    for m in ISSUE_REF_PATTERN.finditer(message):
        issues.add(f"#{m.group(1)}")
    for m in GITHUB_ISSUE_PATTERN.finditer(message):
        issues.add(f"#{m.group(1)}")
    return ",".join(sorted(issues))


# ---------------------------------------------------------------------------
# LLM file summary
# ---------------------------------------------------------------------------

def _get_llm_client():
    """Return (OpenAI client, model) using the same fallback as agent.py."""
    from dotenv import load_dotenv
    from openai import OpenAI
    import httpx

    # Find .env — walk up from this file
    env_dir = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        candidate = os.path.join(env_dir, ".env")
        if os.path.exists(candidate):
            load_dotenv(candidate)
            break
        env_dir = os.path.dirname(env_dir)

    base_url = os.getenv("OPENAI_BASE_URL", "")
    model = os.getenv("OPENAI_MODEL", "deepseek-v4-flash")

    ds_key = os.getenv("OPENAI_DS_API_KEY", "") or os.getenv("OPENAI_DEFAULT_KEY", "")
    if ds_key and base_url:
        return (
            OpenAI(api_key=ds_key, base_url=base_url, max_retries=2,
                   timeout=httpx.Timeout(120.0, connect=30.0)),
            model,
        )

    ds_api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if ds_api_key:
        return (
            OpenAI(api_key=ds_api_key,
                   base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                   max_retries=2,
                   timeout=httpx.Timeout(120.0, connect=30.0)),
            os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash"),
        )

    first_url = os.getenv("USE_FIRST_URL", "")
    first_key = os.getenv("USE_FIRST_KEY", "")
    if first_key and first_url:
        return (
            OpenAI(api_key=first_key, base_url=first_url, max_retries=2,
                   timeout=httpx.Timeout(120.0, connect=30.0)),
            model,
        )

    return None, ""


def _generate_file_summary(
    file_path: str, repo_name: str, client, model: str
) -> str:
    """Generate a one-sentence functionality summary for a file via LLM."""
    prompt = (
        f'Repository "{repo_name}". '
        f'In one sentence, describe what functionality the file "{file_path}" likely implements. '
        f'Respond with ONLY the sentence, no prefix.'
    )
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=200,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"[summary unavailable: {e}]"


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_rms(
    repo_path: str,
    output_db: str,
    max_commits: int = 500,
    top_hotspots: int = 30,
    generate_summaries: bool = True,
) -> str:
    """Build a per-project Repo Memory Store from git commit history.

    Args:
        repo_path: path to the git repository
        output_db: path for the output SQLite database
        max_commits: maximum number of recent commits to index
        top_hotspots: number of hotspot files to track
        generate_summaries: whether to call LLM for file summaries

    Returns:
        output_db path
    """
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        raise ValueError(f"Not a git repository: {repo_path}")

    repo_name = os.path.basename(repo_path)
    print(f"Building RMS for {repo_name} ...")

    # 1. Extract commits ---------------------------------------------------
    print(f"  Extracting up to {max_commits} commits ...")
    commits = _get_commit_list(repo_path, max_commits)
    print(f"  Found {len(commits)} commits")

    # 2. Build BM25 index and collect file stats ---------------------------
    print("  Building BM25 index ...")
    bm25 = BM25Index()
    file_edit_counts: Dict[str, int] = defaultdict(int)
    file_last_modified: Dict[str, str] = {}

    os.makedirs(os.path.dirname(output_db) or ".", exist_ok=True)
    conn = sqlite3.connect(output_db)
    conn.execute("PRAGMA journal_mode=WAL")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS commits (
            sha TEXT PRIMARY KEY,
            message TEXT,
            author TEXT,
            date TEXT,
            linked_issues TEXT,
            patch TEXT,
            modified_files TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_hotspots (
            file_path TEXT PRIMARY KEY,
            edit_count INTEGER,
            last_modified TEXT,
            functionality_summary TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    for i, c in enumerate(commits):
        sha, message = c["sha"], c["message"]

        bm25.add(sha, message)

        try:
            changed = _get_changed_files(repo_path, sha)
        except Exception:
            changed = []

        for f in changed:
            file_edit_counts[f] += 1
            if f not in file_last_modified:
                file_last_modified[f] = c["date"]

        try:
            patch = _get_commit_patch(repo_path, sha)
        except Exception:
            patch = ""

        linked = _extract_linked_issues(message)

        conn.execute(
            "INSERT OR IGNORE INTO commits VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sha, message, c["author"], c["date"], linked, patch, ",".join(changed)),
        )

        if (i + 1) % 100 == 0:
            conn.commit()
            print(f"    {i+1}/{len(commits)} commits ...")

    conn.commit()

    # 3. Hotspot files & LLM summaries -------------------------------------
    sorted_files = sorted(file_edit_counts.items(), key=lambda x: -x[1])[:top_hotspots]

    client, model = None, ""
    if generate_summaries and sorted_files:
        try:
            client, model = _get_llm_client()
        except Exception as e:
            print(f"  Warning: LLM client init failed: {e}")

    for file_path, count in sorted_files:
        summary = ""
        if client and model:
            try:
                summary = _generate_file_summary(file_path, repo_name, client, model)
                print(f"    {file_path}: {summary[:100]}...")
            except Exception as e:
                summary = f"[error: {e}]"

        conn.execute(
            "INSERT OR REPLACE INTO file_hotspots VALUES (?, ?, ?, ?)",
            (file_path, count, file_last_modified.get(file_path, ""), summary),
        )

    # 4. Persist BM25 index -------------------------------------------------
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('bm25_index', ?)",
        (json.dumps(bm25.to_dict()),),
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('repo_path', ?)", (repo_path,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('version', ?)", ("2.0",)
    )

    conn.commit()

    fc = conn.execute("SELECT COUNT(*) FROM file_hotspots").fetchone()[0]
    cc = conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
    print(f"RMS saved: {output_db}")
    print(f"  Commits: {cc}  |  Hotspot files: {fc}  |  BM25 docs: {bm25.N}")
    conn.close()
    return output_db


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Build Repo Memory Store (RepoMem paper)")
    p.add_argument("repo_path", help="Path to git repository")
    p.add_argument("output_db", help="Output SQLite database path")
    p.add_argument("--max-commits", type=int, default=500)
    p.add_argument("--top-hotspots", type=int, default=30)
    p.add_argument("--no-summaries", action="store_true")

    args = p.parse_args()
    build_rms(
        repo_path=args.repo_path,
        output_db=args.output_db,
        max_commits=args.max_commits,
        top_hotspots=args.top_hotspots,
        generate_summaries=not args.no_summaries,
    )
