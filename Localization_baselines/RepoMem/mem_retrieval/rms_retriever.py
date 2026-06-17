"""
RMS Retriever — RepoMem memory access tools.

Implements the three paper tools:
  - SearchCommit(query, top_k)  — BM25 keyword search over commit messages
  - ExamineCommit(sha)          — full commit details + patch + linked issues
  - ViewSummary(file_name)      — cached LLM file functionality summary

All results respect date filtering (commits before issue date) to avoid
contamination, as specified in the RepoMem paper §3.1.
"""

import json
import os
import re
import sqlite3
from collections import defaultdict
from math import log
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# BM25 Index (reconstructed from DB)
# ---------------------------------------------------------------------------

class BM25Index:
    """BM25 over commit messages, reconstructed from serialized state."""

    def __init__(self, k1=1.2, b=0.75):
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
        if self.N > 0:
            self.avg_dl = sum(self.doc_lengths.values()) / self.N

    def search(
        self,
        query: str,
        top_k: int = 10,
        allowed_shas: Optional[set] = None,
    ) -> List[Tuple[str, float]]:
        """Return top-k (sha, score) matches, optionally restricted to allowed_shas."""
        tokens = self._tokenize(query)
        if not tokens:
            return []

        scores: Dict[str, float] = defaultdict(float)
        for token in set(tokens):
            df = self.doc_freq.get(token, 0)
            if df == 0:
                continue
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


# ---------------------------------------------------------------------------
# Retriever
# ---------------------------------------------------------------------------

class RMSRetriever:
    """Query interface for a per-project Repo Memory Store."""

    def __init__(self, db_path: str):
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"RMS DB not found: {db_path}")

        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row

        # Load BM25 index from meta
        self._bm25: Optional[BM25Index] = None
        self._bm25_ready = False
        self._repo_path: str = ""

        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='repo_path'"
        ).fetchone()
        if row:
            self._repo_path = row[0]

    # ------------------------------------------------------------------
    # Paper tools
    # ------------------------------------------------------------------

    def search_commit(
        self, query: str, top_k: int = 10, before_date: str = ""
    ) -> List[dict]:
        """Search commits by BM25 over commit messages.

        Corresponds to SearchCommit(query, top_k) in the paper.

        Args:
            query: free-text query (typically CVE title + description)
            top_k: number of results
            before_date: ISO date string; only include commits BEFORE this date
                          (contamination filter per paper §3.1)

        Returns:
            [{sha, message, author, date, score, linked_issues}, ...]
        """
        self._ensure_bm25()

        allowed: Optional[set] = None
        if before_date:
            rows = self._conn.execute(
                "SELECT sha FROM commits WHERE date < ?", (before_date,)
            ).fetchall()
            allowed = {r[0] for r in rows}
            if not allowed:
                return []

        hits = self._bm25.search(query, top_k=top_k, allowed_shas=allowed)

        results = []
        for sha, score in hits:
            row = self._conn.execute(
                "SELECT sha, message, author, date, linked_issues FROM commits WHERE sha=?",
                (sha,),
            ).fetchone()
            if row:
                results.append({
                    "sha": row["sha"],
                    "message": row["message"],
                    "author": row["author"],
                    "date": row["date"],
                    "score": round(score, 6),
                    "linked_issues": row["linked_issues"] or "",
                })
        return results

    def examine_commit(self, sha: str) -> Optional[dict]:
        """Return full details for a commit, including the patch.

        Corresponds to ExamineCommit(id) in the paper.

        Returns:
            {sha, message, author, date, linked_issues, patch, modified_files}
            or None if not found.
        """
        row = self._conn.execute(
            "SELECT * FROM commits WHERE sha=?", (sha,)
        ).fetchone()
        if not row:
            return None
        return {
            "sha": row["sha"],
            "message": row["message"],
            "author": row["author"],
            "date": row["date"],
            "linked_issues": row["linked_issues"] or "",
            "patch": row["patch"] or "",
            "modified_files": (row["modified_files"] or "").split(",")
            if row["modified_files"] else [],
        }

    def view_summary(self, file_name: str) -> Optional[str]:
        """Return the cached LLM functionality summary for a file.

        Corresponds to ViewSummary(file_name) in the paper.

        Performs partial-path matching: exact first, then basename, then LIKE.
        """
        # Exact match
        row = self._conn.execute(
            "SELECT functionality_summary FROM file_hotspots WHERE file_path=?",
            (file_name,),
        ).fetchone()
        if row and row[0]:
            return row[0]

        # Basename match
        bn = os.path.basename(file_name)
        row = self._conn.execute(
            "SELECT file_path, functionality_summary FROM file_hotspots "
            "WHERE file_path LIKE ? LIMIT 1",
            (f"%{bn}%",),
        ).fetchone()
        if row and row[1]:
            return f"[{row[0]}]: {row[1]}"

        return None

    # ------------------------------------------------------------------
    # Convenience: get hotspot files
    # ------------------------------------------------------------------

    def get_hotspots(self, top_k: int = 30) -> List[dict]:
        """Return top hotspot files with their summaries."""
        rows = self._conn.execute(
            "SELECT * FROM file_hotspots ORDER BY edit_count DESC LIMIT ?",
            (top_k,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_summaries(self) -> Dict[str, str]:
        """Return {file_path: summary} for all hotspot files."""
        rows = self._conn.execute(
            "SELECT file_path, functionality_summary FROM file_hotspots "
            "WHERE functionality_summary IS NOT NULL AND functionality_summary != ''"
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        cc = self._conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
        hc = self._conn.execute("SELECT COUNT(*) FROM file_hotspots").fetchone()[0]
        return {
            "commits": cc,
            "hotspots": hc,
            "repo_path": self._repo_path,
        }

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Internal: BM25 loading
    # ------------------------------------------------------------------

    def _ensure_bm25(self):
        """Lazy-load and reconstruct BM25 index from DB."""
        if self._bm25_ready:
            return

        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='bm25_index'"
        ).fetchone()
        if not row:
            # Build BM25 from commits table on-the-fly
            self._bm25 = BM25Index()
            for r in self._conn.execute("SELECT sha, message FROM commits").fetchall():
                self._bm25.add(r[0], r[1])
        else:
            data = json.loads(row[0])
            self._bm25 = BM25Index(k1=data["k1"], b=data["b"])
            self._bm25.N = data["N"]
            self._bm25.avg_dl = data["avg_dl"]
            self._bm25.doc_freq = defaultdict(int, data["doc_freq"])
            self._bm25.doc_lengths = data["doc_lengths"]
            self._bm25.term_freqs = data["term_freqs"]
            # Re-populate docs dict from DB
            for r in self._conn.execute("SELECT sha, message FROM commits").fetchall():
                self._bm25.docs[r[0]] = r[1]

        self._bm25_ready = True


# ---------------------------------------------------------------------------
# Git Direct Retriever — fallback when no pre-built RMS DB exists
# ---------------------------------------------------------------------------

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
ISSUE_REF_PATTERN = re.compile(
    r'(?:fix|close|resolve|address)(?:es|ed|s)?\s+#(\d+)', re.IGNORECASE
)
GITHUB_ISSUE_PATTERN = re.compile(
    r'(?:github\.com/[\w.-]+/[\w.-]+/issues/)(\d+)', re.IGNORECASE
)


class GitDirectRetriever:
    """Same interface as RMSRetriever, but queries git repo directly.

    Used as fallback when no pre-built RMS SQLite DB exists.
    Builds a temporary BM25 index from git log on first search.
    """

    def __init__(self, repo_path: str, max_commits: int = 500):
        if not os.path.isdir(os.path.join(repo_path, ".git")):
            raise FileNotFoundError(f"Not a git repository: {repo_path}")

        self._repo_path = repo_path
        self._max_commits = max_commits
        self._bm25: Optional[BM25Index] = None
        self._commits: Dict[str, dict] = {}  # sha -> commit info
        self._file_counts: Dict[str, int] = defaultdict(int)
        self._built = False

    # ------------------------------------------------------------------
    # Paper tools
    # ------------------------------------------------------------------

    def search_commit(
        self, query: str, top_k: int = 10, before_date: str = ""
    ) -> List[dict]:
        """BM25 search over commit messages from git log."""
        self._ensure_built()

        allowed: Optional[set] = None
        if before_date:
            allowed = {sha for sha, c in self._commits.items()
                       if c["date"] < before_date}
            if not allowed:
                return []

        hits = self._bm25.search(query, top_k=top_k, allowed_shas=allowed)

        results = []
        for sha, score in hits:
            c = self._commits.get(sha)
            if c:
                results.append({
                    "sha": sha,
                    "message": c["message"],
                    "author": c["author"],
                    "date": c["date"],
                    "score": round(score, 6),
                    "linked_issues": c.get("linked_issues", ""),
                })
        return results

    def examine_commit(self, sha: str) -> Optional[dict]:
        """Return full commit details using git show/diff-tree."""
        import subprocess

        # Check cache first
        cached = self._commits.get(sha, {})

        # Get patch
        try:
            patch = subprocess.run(
                ["git", "-C", self._repo_path, "diff-tree", "--no-commit-id", "-p", sha],
                capture_output=True, text=True, timeout=30,
            ).stdout
        except Exception:
            patch = ""

        # Get modified files
        try:
            files_out = subprocess.run(
                ["git", "-C", self._repo_path, "diff-tree", "--no-commit-id",
                 "--name-only", "-r", sha],
                capture_output=True, text=True, timeout=30,
            ).stdout
            modified_files = [f.strip() for f in files_out.split("\n") if f.strip()]
        except Exception:
            modified_files = []

        # Get full commit info if not cached
        if not cached:
            try:
                info = subprocess.run(
                    ["git", "-C", self._repo_path, "log", "--pretty=format:%H|%s|%an|%aI",
                     "-n1", sha],
                    capture_output=True, text=True, timeout=30,
                ).stdout.strip()
                parts = info.split("|", 3)
                if len(parts) >= 4:
                    cached = {
                        "sha": parts[0], "message": parts[1],
                        "author": parts[2], "date": parts[3],
                    }
            except Exception:
                cached = {}

        message = cached.get("message", "")
        linked = self._extract_linked_issues(message)

        return {
            "sha": sha,
            "message": message,
            "author": cached.get("author", ""),
            "date": cached.get("date", ""),
            "linked_issues": linked,
            "patch": patch,
            "modified_files": modified_files,
        }

    def view_summary(self, file_name: str) -> Optional[str]:
        """No cached summaries available in direct mode. Returns None."""
        return None

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def get_hotspots(self, top_k: int = 30) -> List[dict]:
        """Return top hotspot files from git log frequency."""
        self._ensure_built()
        sorted_files = sorted(self._file_counts.items(), key=lambda x: -x[1])[:top_k]
        return [
            {"file_path": f, "edit_count": c, "last_modified": "",
             "functionality_summary": ""}
            for f, c in sorted_files
        ]

    def get_all_summaries(self) -> Dict[str, str]:
        """No summaries available in direct mode."""
        return {}

    def stats(self) -> dict:
        self._ensure_built()
        return {
            "commits": len(self._commits),
            "hotspots": len(self._file_counts),
            "repo_path": self._repo_path,
        }

    def close(self):
        self._commits.clear()
        self._file_counts.clear()
        self._bm25 = None
        self._built = False

    # ------------------------------------------------------------------
    # Internal: build BM25 from git log
    # ------------------------------------------------------------------

    def _ensure_built(self):
        if self._built:
            return
        import subprocess

        print(f"  [GIT] Building BM25 index from git log ({self._max_commits} commits)...")

        # Get commit list
        result = subprocess.run(
            ["git", "-C", self._repo_path, "log", "--all",
             "--pretty=format:%H|%s|%an|%aI", f"-n{self._max_commits}"],
            capture_output=True, text=True, timeout=120,
        )

        self._bm25 = BM25Index()

        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("|", 3)
            if len(parts) < 4:
                continue
            sha, message, author, date = parts[0], parts[1], parts[2], parts[3]

            self._bm25.add(sha, message)
            linked = self._extract_linked_issues(message)

            self._commits[sha] = {
                "sha": sha, "message": message, "author": author,
                "date": date, "linked_issues": linked,
            }

        # Get file frequencies
        try:
            files_out = subprocess.run(
                ["git", "-C", self._repo_path, "log", "--all",
                 "--pretty=format:", "--name-only", f"-n{self._max_commits}"],
                capture_output=True, text=True, timeout=120,
            )
            for f in files_out.stdout.strip().split("\n"):
                f = f.strip()
                if f:
                    self._file_counts[f] += 1
        except Exception:
            pass

        self._built = True
        print(f"  [GIT] Indexed {len(self._commits)} commits, "
              f"{len(self._file_counts)} files")

    @staticmethod
    def _extract_linked_issues(message: str) -> str:
        issues: set = set()
        for m in CVE_PATTERN.finditer(message):
            issues.add(m.group(0).upper())
        for m in ISSUE_REF_PATTERN.finditer(message):
            issues.add(f"#{m.group(1)}")
        for m in GITHUB_ISSUE_PATTERN.finditer(message):
            issues.add(f"#{m.group(1)}")
        return ",".join(sorted(issues))
