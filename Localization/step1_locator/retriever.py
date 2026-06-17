"""
Retriever — joint BM25 + issue-aware retrieval for the Localization pipeline.

Combines:
  - BM25 keyword search over commit messages (from RMS)
  - Issue-aware search in issue_links table
  - before_date filter (anti-leakage: excludes fix commits)
  - Directory tree listing

Reuses BM25Index from step1_locator/memory_store.py.
"""

import json
import os
import re
import sqlite3
from collections import defaultdict
from math import log
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# BM25 Index (reconstructed from DB, same as memory_store.py)
# ---------------------------------------------------------------------------

class BM25Index:
    """BM25 over commit messages."""

    def __init__(self, k1=1.2, b=0.75):
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
        if self.N > 0:
            self.avg_dl = sum(self.doc_lengths.values()) / self.N

    def search(
        self, query: str, top_k: int = 10,
        allowed_shas: Optional[set] = None,
    ) -> List[Tuple[str, float]]:
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

class Retriever:
    """Query interface for the enhanced Repo Memory Store.

    Provides:
      - search_commit(query, top_k, before_date)  — BM25 over commits
      - examine_commit(sha)                        — full commit details
      - search_issues(description, top_k)          — issue_links search
      - list_directory(path, depth)                — directory tree
      - get_hotspots(top_k)                        — hotspot files
    """

    def __init__(self, db_path: str, repo_path: str = ""):
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"RMS DB not found: {db_path}")

        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._bm25: Optional[BM25Index] = None
        self._bm25_ready = False
        self.repo_path = repo_path

        # Try to get repo_path from meta if not provided
        if not self.repo_path:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key='repo_path'"
            ).fetchone()
            if row:
                self.repo_path = row[0]

    # ------------------------------------------------------------------
    # search_commit — BM25 keyword search over commit messages
    # ------------------------------------------------------------------

    def search_commit(
        self, query: str, top_k: int = 10, before_date: str = ""
    ) -> List[dict]:
        """BM25 search over commit messages with date filter.

        Args:
            query: free-text query (CVE title + description)
            top_k: number of results
            before_date: ISO date string; only include commits BEFORE this date.
                         Falls back to no filter if all commits excluded.
        """
        self._ensure_bm25()

        allowed: Optional[set] = None
        if before_date:
            rows = self._conn.execute(
                "SELECT sha FROM commits WHERE date < ?", (before_date,)
            ).fetchall()
            allowed = {r[0] for r in rows}
            if not allowed:
                # Check meta fallback flag for context
                fb_row = self._conn.execute(
                    "SELECT value FROM meta WHERE key='fallback'"
                ).fetchone()
                fallback = fb_row[0] if fb_row else ""
                if fallback == "date_unavailable":
                    print(f"  [RETRIEVER] Date unavailable (mirrored repo), "
                          f"using all commits — fallback={fallback}")
                elif fallback == "no_date_available":
                    print(f"  [RETRIEVER] No date info available for CVE, "
                          f"using all commits — fallback={fallback}")
                else:
                    print(f"  [RETRIEVER] No commits before {before_date[:10]}, "
                          f"falling back to all commits")

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

    # ------------------------------------------------------------------
    # examine_commit — full details for a commit
    # ------------------------------------------------------------------

    def examine_commit(self, sha: str) -> Optional[dict]:
        """Return full commit details including patch and modified files."""
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

    # ------------------------------------------------------------------
    # search_issues — issue links table search
    # ------------------------------------------------------------------

    def search_issues(self, query: str, top_k: int = 5) -> List[dict]:
        """Search resolved issues by keyword matching title/body.

        Simple keyword overlap scoring — ranks issues whose title/body
        contain query terms.
        """
        query_terms = set(re.findall(r'[a-z0-9]{2,}', query.lower()))
        if not query_terms:
            return []

        rows = self._conn.execute(
            "SELECT * FROM issue_links WHERE commit_sha != ''"
        ).fetchall()

        scored = []
        for row in rows:
            text = f"{row['title'] or ''} {row['body'] or ''}".lower()
            score = sum(1 for t in query_terms if t in text)
            if score > 0:
                scored.append((score, dict(row)))

        scored.sort(key=lambda x: -x[0])
        return [item for _, item in scored[:top_k]]

    def get_issue_by_number(self, issue_number: int) -> Optional[dict]:
        """Get a specific issue link by issue number."""
        row = self._conn.execute(
            "SELECT * FROM issue_links WHERE issue_number=?", (issue_number,)
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # get_hotspots — most frequently edited files
    # ------------------------------------------------------------------

    def get_hotspots(self, top_k: int = 30) -> List[dict]:
        """Return top hotspot files with edit counts."""
        rows = self._conn.execute(
            "SELECT * FROM file_hotspots ORDER BY edit_count DESC LIMIT ?",
            (top_k,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # list_directory — directory tree listing
    # ------------------------------------------------------------------

    def list_directory(self, path: str = "", depth: int = 3) -> str:
        """Return directory tree of the repo as formatted text.

        Uses os.walk for the repo filesystem if available,
        falls back to git ls-tree.
        """
        base = self.repo_path
        if path:
            base = os.path.join(self.repo_path, path)

        if not os.path.isdir(base):
            return f"Directory not found: {path}"

        lines = []
        for root, dirs, files in os.walk(base):
            rel = os.path.relpath(root, self.repo_path)
            if rel == ".":
                rel = ""

            # Compute depth
            current_depth = len(rel.split(os.sep)) if rel else 0
            if current_depth >= depth:
                dirs.clear()  # don't go deeper
                continue

            # Skip hidden dirs and common ignore patterns
            dirs[:] = [d for d in dirs if not d.startswith(".")
                       and d not in ("node_modules", "__pycache__", ".git",
                                     "vendor", "target", "build", "dist")]

            indent = "  " * current_depth
            dir_name = os.path.basename(root) if rel else os.path.basename(self.repo_path)
            lines.append(f"{indent}{dir_name}/")

            for f in sorted(files):
                if f.startswith("."):
                    continue
                lines.append(f"{indent}  {f}")

        return "\n".join(lines[:200])  # cap at 200 lines

    # ------------------------------------------------------------------
    # get_file_set — all files referenced in matching commits
    # ------------------------------------------------------------------

    def get_files_from_commits(self, shas: List[str]) -> List[str]:
        """Return unique modified files from a list of commit SHAs."""
        files: set = set()
        for sha in shas:
            row = self._conn.execute(
                "SELECT modified_files FROM commits WHERE sha=?", (sha,)
            ).fetchone()
            if row and row[0]:
                files.update(f.strip() for f in row[0].split(",") if f.strip())
        return sorted(files)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        cc = self._conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
        hc = self._conn.execute("SELECT COUNT(*) FROM file_hotspots").fetchone()[0]
        ic = self._conn.execute("SELECT COUNT(*) FROM issue_links WHERE commit_sha != ''").fetchone()[0]
        return {
            "commits": cc,
            "hotspots": hc,
            "linked_issues": ic,
            "repo_path": self.repo_path,
        }

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # BM25 lazy loading
    # ------------------------------------------------------------------

    def _ensure_bm25(self):
        if self._bm25_ready:
            return
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='bm25_index'"
        ).fetchone()
        if row:
            data = json.loads(row[0])
            self._bm25 = BM25Index(k1=data["k1"], b=data["b"])
            self._bm25.N = data["N"]
            self._bm25.avg_dl = data["avg_dl"]
            self._bm25.doc_freq = defaultdict(int, data["doc_freq"])
            self._bm25.doc_lengths = data["doc_lengths"]
            self._bm25.term_freqs = data["term_freqs"]
        else:
            self._bm25 = BM25Index()

        # Populate docs dict from DB
        for r in self._conn.execute("SELECT sha, message FROM commits").fetchall():
            if r[0] not in self._bm25.docs:
                self._bm25.docs[r[0]] = r[1]
        self._bm25_ready = True


# ---------------------------------------------------------------------------
# NoKGRetriever — zero-KG stub for ablation experiments
# ---------------------------------------------------------------------------

class NoKGRetriever:
    """Stub retriever that returns empty results for all KG queries.

    Used for ablation study: agent works without RMS DB, BM25, issue links,
    or hotspot files. Only directory listing works (via os.walk).
    """

    def __init__(self, repo_path: str = ""):
        self.repo_path = repo_path

    def search_commit(self, query: str, top_k: int = 10, before_date: str = "") -> List[dict]:
        return []

    def examine_commit(self, sha: str) -> Optional[dict]:
        return None

    def search_issues(self, query: str, top_k: int = 5) -> List[dict]:
        return []

    def get_issue_by_number(self, issue_number: int) -> Optional[dict]:
        return None

    def get_hotspots(self, top_k: int = 30) -> List[dict]:
        return []

    def get_files_from_commits(self, shas: List[str]) -> List[str]:
        return []

    def list_directory(self, path: str = "", depth: int = 3) -> str:
        base = os.path.join(self.repo_path, path) if path else self.repo_path
        if not os.path.isdir(base):
            return f"Directory not found: {path}"

        lines = []
        for root, dirs, files in os.walk(base):
            rel = os.path.relpath(root, self.repo_path)
            if rel == ".":
                rel = ""

            current_depth = len(rel.split(os.sep)) if rel else 0
            if current_depth >= depth:
                dirs.clear()
                continue

            dirs[:] = [d for d in dirs if not d.startswith(".")
                       and d not in ("node_modules", "__pycache__", ".git",
                                     "vendor", "target", "build", "dist")]

            indent = "  " * current_depth
            dir_name = os.path.basename(root) if rel else os.path.basename(self.repo_path)
            lines.append(f"{indent}{dir_name}/")

            for f in sorted(files):
                if f.startswith("."):
                    continue
                lines.append(f"{indent}  {f}")

        return "\n".join(lines[:200])

    def stats(self) -> dict:
        return {"commits": 0, "hotspots": 0, "linked_issues": 0,
                "repo_path": self.repo_path, "mode": "no_kg"}

    def close(self):
        pass
