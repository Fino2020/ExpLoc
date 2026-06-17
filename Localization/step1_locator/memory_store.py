"""
Enhanced Repo Memory Store — SQLite builder for the Localization pipeline.

Extends RepoMem's RMS with an issue_links table that maps GitHub issues
to resolution commits, discovered via git log scanning (issue_linker.py).

Schema:
  commits(sha, message, author, date, linked_issues, patch, modified_files)
  file_hotspots(file_path, edit_count, last_modified, functionality_summary)
  issue_links(issue_number, repo_key, title, body, state, pr_number,
              commit_sha, changed_files, changed_functions, resolved_at, labels)
  meta(key, value)

Builds from git log only — NEVER reads dataset files (anti-leakage).
"""

import json
import os
import re
import sqlite3
import subprocess
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
ISSUE_REF_PATTERN = re.compile(
    r'(?:fix|close|resolve|address)(?:es|ed|s)?\s+#(\d+)', re.IGNORECASE
)
GITHUB_ISSUE_PATTERN = re.compile(
    r'(?:github\.com/[\w.-]+/[\w.-]+/issues/)(\d+)', re.IGNORECASE
)

# Patterns for non-source files to exclude from hotspot ranking.
# Build, CI, doc, config, test, and generated artifacts dominate edit counts
# without contributing to vulnerability localization signal.
_NON_SOURCE_DIRS = {
    'abi-check', '.github', '.circleci', '.travis', 'travis-ci',
    'node_modules', '__pycache__', 'vendor', 'third_party', 'external',
    '.svn', '.hg', 'target', 'build', 'dist', 'out', '.deps',
}
_NON_SOURCE_EXTS = {
    '.html', '.css', '.so', '.a', '.o', '.dylib', '.dll', '.pdb', '.exe',
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf', '.ttf', '.woff',
    '.eot', '.csv', '.tsv', '.lock', '.sum',
}
_NON_SOURCE_NAMES = {
    'Makefile', 'makefile', 'GNUmakefile', 'CMakeLists.txt',
    'configure', 'autogen.sh', 'config.guess', 'config.sub',
    '.travis.yml', 'appveyor.yml', 'Jenkinsfile', 'Dockerfile',
    '.gitignore', '.gitattributes', '.gitmodules', '.editorconfig',
    'package.json', 'package-lock.json', 'yarn.lock', 'Cargo.lock',
    'Gemfile.lock', 'go.sum', 'Pipfile.lock', 'poetry.lock',
    'setup.py', 'setup.cfg', 'pyproject.toml',
}
_NON_SOURCE_PREFIXES = {
    'README', 'CHANGES', 'CHANGELOG', 'NEWS', 'LICENSE', 'COPYING',
    'AUTHORS', 'CONTRIBUTING', 'TODO', 'INSTALL', 'RELEASE', 'HISTORY',
}


def _is_source_file(filepath: str) -> bool:
    """Return True if filepath looks like a source file (not build/CI/doc/config)."""
    parts = filepath.replace('\\', '/').split('/')

    # Exclude known non-source directories at any depth
    for part in parts:
        if part in _NON_SOURCE_DIRS:
            return False

    filename = parts[-1] if parts else filepath
    basename = os.path.splitext(filename)[0]
    ext = os.path.splitext(filename)[1].lower()

    # Exclude by extension
    if ext in _NON_SOURCE_EXTS:
        return False

    # Exclude by exact filename
    if filename in _NON_SOURCE_NAMES:
        return False

    # Exclude by filename prefix (README.md, CHANGELOG.rst, etc.)
    if basename in _NON_SOURCE_PREFIXES:
        return False
    for prefix in _NON_SOURCE_PREFIXES:
        if basename.startswith(prefix) or basename.startswith(prefix.lower()):
            return False

    return True


# ---------------------------------------------------------------------------
# BM25 Index
# ---------------------------------------------------------------------------

class BM25Index:
    """BM25 ranking over commit messages. k1=1.2, b=0.75."""

    def __init__(self, k1: float = 1.2, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.docs: Dict[str, str] = {}
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

    def search(self, query: str, top_k: int = 10,
               allowed_shas: Optional[set] = None) -> List[Tuple[str, float]]:
        tokens = self._tokenize(query)
        if not tokens:
            return []
        scores: Dict[str, float] = defaultdict(float)
        for token in set(tokens):
            df = self.doc_freq.get(token, 0)
            if df == 0:
                continue
            from math import log
            idf = log((self.N - df + 0.5) / (df + 0.5) + 1.0)
            for doc_id in self.docs:
                if allowed_shas is not None and doc_id not in allowed_shas:
                    continue
                tf = self.term_freqs.get(doc_id, {}).get(token, 0)
                if tf == 0:
                    continue
                dl = self.doc_lengths[doc_id]
                numerator = tf * (self.k1 + 1)
                denominator = tf + self.k1 * (1 - self.b + self.b * dl / max(self.avg_dl, 1))
                scores[doc_id] += idf * numerator / denominator
        return sorted(scores.items(), key=lambda x: -x[1])[:top_k]

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
        idx.docs = {}
        return idx


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS commits (
    sha TEXT PRIMARY KEY,
    message TEXT,
    author TEXT,
    date TEXT,
    linked_issues TEXT,
    patch TEXT,
    modified_files TEXT
);

CREATE TABLE IF NOT EXISTS file_hotspots (
    file_path TEXT PRIMARY KEY,
    edit_count INTEGER,
    last_modified TEXT,
    functionality_summary TEXT
);

CREATE TABLE IF NOT EXISTS issue_links (
    issue_number INTEGER,
    repo_key TEXT,
    title TEXT,
    body TEXT,
    state TEXT,
    pr_number INTEGER,
    commit_sha TEXT,
    changed_files TEXT,
    changed_functions TEXT,
    resolved_at TEXT,
    labels TEXT,
    PRIMARY KEY (issue_number, repo_key)
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _run_git(repo_path: str, args: List[str], timeout: int = 60) -> str:
    result = subprocess.run(
        ["git", "-C", repo_path] + args,
        capture_output=True, text=True, timeout=timeout,
    )
    return result.stdout


def _get_commit_list(repo_path: str, max_commits: int = 500,
                     before_date: str = "") -> List[dict]:
    args = ["log", "--all", "--pretty=format:%H|%s|%an|%aI", f"-n{max_commits}"]
    if before_date:
        args.insert(1, f"--before={before_date}")
    output = _run_git(repo_path, args, timeout=300)
    commits = []
    for line in output.strip().split("\n"):
        if not line:
            continue
        parts = line.split("|", 3)
        if len(parts) >= 4:
            commits.append({
                "sha": parts[0], "message": parts[1],
                "author": parts[2], "date": parts[3],
            })
    return commits


def _get_commit_patch(repo_path: str, sha: str) -> str:
    return _run_git(repo_path, ["diff-tree", "--no-commit-id", "-p", sha], timeout=30)


def _get_changed_files(repo_path: str, sha: str) -> List[str]:
    output = _run_git(
        repo_path, ["diff-tree", "--no-commit-id", "--name-only", "-r", sha], timeout=30
    )
    return [f.strip() for f in output.split("\n") if f.strip()]


def _extract_linked_issues(message: str) -> str:
    issues: set = set()
    for m in CVE_PATTERN.finditer(message):
        issues.add(m.group(0).upper())
    for m in ISSUE_REF_PATTERN.finditer(message):
        issues.add(f"#{m.group(1)}")
    for m in GITHUB_ISSUE_PATTERN.finditer(message):
        issues.add(f"#{m.group(1)}")
    return ",".join(sorted(issues))


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_rms(
    repo_path: str,
    output_db: str,
    max_commits: int = 500,
    top_hotspots: int = 30,
    before_date: str = "",
    fallback: str = "none",
) -> str:
    """Build a per-project Repo Memory Store from git commit history.

    Populates commits, file_hotspots, and issue_links (initially empty).
    issue_links is filled later by issue_linker.py.

    Returns output_db path.
    """
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        raise ValueError(f"Not a git repository: {repo_path}")

    repo_name = os.path.basename(repo_path)
    print(f"Building RMS for {repo_name} ...")

    commits = _get_commit_list(repo_path, max_commits, before_date=before_date)
    print(f"  Found {len(commits)} commits"
          + (f" (before {before_date[:10]})" if before_date else ""))

    bm25 = BM25Index()
    file_edit_counts: Dict[str, int] = defaultdict(int)
    file_last_modified: Dict[str, str] = {}

    os.makedirs(os.path.dirname(output_db) or ".", exist_ok=True)
    conn = sqlite3.connect(output_db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA_DDL)

    for i, c in enumerate(commits):
        sha, message = c["sha"], c["message"]
        bm25.add(sha, message)

        try:
            changed = _get_changed_files(repo_path, sha)
        except Exception:
            changed = []

        for f in changed:
            if _is_source_file(f):
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

    # Hotspot files
    sorted_files = sorted(file_edit_counts.items(), key=lambda x: -x[1])[:top_hotspots]
    for file_path, count in sorted_files:
        conn.execute(
            "INSERT OR REPLACE INTO file_hotspots VALUES (?, ?, ?, ?)",
            (file_path, count, file_last_modified.get(file_path, ""), ""),
        )

    # Persist BM25 and meta
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('bm25_index', ?)",
        (json.dumps(bm25.to_dict()),),
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('repo_path', ?)", (repo_path,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('version', ?)", ("3.0",)
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('before_date', ?)", (before_date,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES ('fallback', ?)", (fallback,)
    )

    conn.commit()

    fc = conn.execute("SELECT COUNT(*) FROM file_hotspots").fetchone()[0]
    cc = conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
    print(f"RMS saved: {output_db}")
    print(f"  Commits: {cc}  |  Hotspot files: {fc}  |  BM25 docs: {bm25.N}")
    conn.close()
    return output_db
