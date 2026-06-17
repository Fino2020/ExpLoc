"""
RepoMem Localizer — per-project memory-augmented vulnerability localization.

Loads a per-project Repo Memory Store (RMS) or falls back to direct git
queries, runs the LLM Agent with commit-history memory tools, and produces
ranked, explainable localization results.

Implements the RepoMem paper (ICLR 2026).
"""

import json
import os
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mem_retrieval.rms_retriever import RMSRetriever, GitDirectRetriever
from agent.agent import RepoMemAgent


class RepoMemLocalizer:
    """Top-level localizer: loads RMS or git-direct retriever, runs agent."""

    def __init__(self, rms_db_path: str = "", repo_path: str = ""):
        """Initialize with either a pre-built RMS DB or a git repo path.

        Args:
            rms_db_path: path to per-project .db file built by build_rms.py
            repo_path: path to git repo (fallback when no RMS DB exists)
        """
        self.rms_db_path = rms_db_path
        self.repo_path = repo_path
        self._retriever = None  # RMSRetriever or GitDirectRetriever
        self._agent: Optional[RepoMemAgent] = None
        self._use_direct_git = False

    @property
    def rms(self):
        """Return the retriever (RMSRetriever or GitDirectRetriever)."""
        if self._retriever is None:
            if self.rms_db_path and os.path.exists(self.rms_db_path):
                self._retriever = RMSRetriever(self.rms_db_path)
                self._use_direct_git = False
                print(f"  [LOCALIZER] Using pre-built RMS: {self.rms_db_path}")
            elif self.repo_path and os.path.isdir(
                os.path.join(self.repo_path, ".git")
            ):
                self._retriever = GitDirectRetriever(self.repo_path)
                self._use_direct_git = True
                print(f"  [LOCALIZER] Using direct git: {self.repo_path}")
            else:
                raise FileNotFoundError(
                    f"Neither RMS DB ({self.rms_db_path}) nor git repo "
                    f"({self.repo_path}) found"
                )
        return self._retriever

    @property
    def agent(self) -> RepoMemAgent:
        if self._agent is None:
            self._agent = RepoMemAgent(rms=self.rms)
        return self._agent

    def localize(
        self,
        cve_id: str,
        issue_title: str,
        issue_body: str,
        language: str = "",
        before_date: str = "",
    ) -> dict:
        """Run memory-augmented localization for a single CVE.

        Args:
            cve_id: CVE identifier
            issue_title: CVE/issue title
            issue_body: CVE/issue description body
            language: programming language
            before_date: ISO date string; only use commits before this date
                         (contamination filter per paper §3.1)

        Returns:
            dict with vulnerable_files, vulnerable_functions, analysis_summary,
            exploration_log, memory_stats
        """
        issue_description = f"Title: {issue_title}\n\nDescription:\n{issue_body}"

        print(f"  [LOCALIZER] Analyzing {cve_id} ({language}) ...")

        result = self.agent.analyze(
            issue_description=issue_description,
            language=language,
            before_date=before_date,
        )

        # Deduplicate: keep highest score per file/function
        seen_files: Dict[str, dict] = {}
        for vf in result.get("vulnerable_files", []):
            fpath = vf.get("file", "").strip().lstrip("./")
            if fpath and fpath not in seen_files:
                seen_files[fpath] = vf

        seen_funcs: Dict[str, dict] = {}
        for vf in result.get("vulnerable_functions", []):
            fname = vf.get("function", "").strip()
            if fname and fname not in seen_funcs:
                seen_funcs[fname] = vf

        output = {
            "cve_id": cve_id,
            "language": language,
            "vulnerable_files": sorted(
                seen_files.values(), key=lambda x: -x.get("score", 0)
            ),
            "vulnerable_functions": sorted(
                seen_funcs.values(), key=lambda x: -x.get("score", 0)
            ),
            "analysis_summary": result.get("analysis_summary", ""),
            "exploration_log": list(self.agent.exploration_log),
            "memory_stats": self.rms.stats(),
        }

        return output

    def close(self):
        if self._retriever:
            self._retriever.close()
            self._retriever = None
