"""
KG Retriever — query the RepoMem Knowledge Graph.

Provides:
  - search_similar_issues: TF-IDF weighted keyword search over issue nodes
  - get_issue_files: files associated with an issue
  - get_issue_functions: functions associated with an issue
  - get_cve_context: full context for a CVE
"""

import json
import os
import re
import math
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

# XML 1.0 invalid control characters (only 0x09, 0x0A, 0x0D are allowed)
_INVALID_XML_BYTES = bytes(set(range(32)) - {9, 10, 13})


def _sanitize_graphml(path: str) -> str:
    """Remove invalid XML bytes from a GraphML file."""
    with open(path, 'rb') as f:
        data = f.read()

    if not any(b in data for b in _INVALID_XML_BYTES):
        return path

    # Backup and fix
    bak = path + ".bak"
    with open(bak, 'wb') as f:
        f.write(data)

    cleaned = data.translate(bytes.maketrans(
        bytes({b: 32 for b in _INVALID_XML_BYTES})
    ))
    with open(path, 'wb') as f:
        f.write(cleaned)
    return path


class KGRetriever:
    def __init__(self, kg_path: str, index_path: str = ""):
        if not os.path.exists(kg_path):
            raise FileNotFoundError(f"KG not found: {kg_path}")

        kg_path = _sanitize_graphml(kg_path)
        self.G = nx.read_graphml(kg_path)
        self.kg_path = kg_path

        # Build inverted indices
        self._issue_nodes: Dict[str, dict] = {}
        self._cve_nodes: Dict[str, dict] = {}
        self._file_to_issues: Dict[str, List[str]] = defaultdict(list)
        self._func_to_issues: Dict[str, List[str]] = defaultdict(list)
        self._issue_to_files: Dict[str, List[str]] = defaultdict(list)
        self._issue_to_funcs: Dict[str, List[str]] = defaultdict(list)
        self._file_df: Dict[str, int] = defaultdict(int)  # document frequency

        for nid, data in self.G.nodes(data=True):
            ntype = data.get("node_type", "")
            if ntype == "Issue":
                self._issue_nodes[nid] = dict(data)
            elif ntype == "CVE":
                self._cve_nodes[nid] = dict(data)

        # Build file/function → issues mapping
        for src, dst, data in self.G.edges(data=True):
            etype = data.get("edge_type", "")
            if etype == "MENTIONS_FILE":
                self._file_to_issues[dst].append(src)
                self._issue_to_files[src].append(dst)
                self._file_df[dst] += 1
            elif etype == "MENTIONS_FUNCTION":
                self._func_to_issues[dst].append(src)
                self._issue_to_funcs[src].append(dst)

        # Load index if available
        self._index: Dict[str, dict] = {}
        if index_path and os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                self._index = json.load(f)

    # ------------------------------------------------------------------
    # Search similar issues
    # ------------------------------------------------------------------

    def search_similar_issues(
        self, query: str, top_k: int = 10, language: str = ""
    ) -> List[Tuple[dict, float]]:
        """TF-IDF weighted search for issues similar to the query.

        Returns list of (issue_data, score) sorted by relevance.
        """
        query_terms = self._tokenize(query)
        if not query_terms:
            return []

        # Compute IDF for query terms
        N = max(len(self._issue_nodes), 1)
        term_idf: Dict[str, float] = {}
        for term in query_terms:
            df = self._file_df.get(term, 0)
            term_idf[term] = math.log((N + 1) / (df + 1)) + 1.0

        scores: List[Tuple[str, float]] = []
        for issue_id, data in self._issue_nodes.items():
            if language and data.get("language", "") != language:
                continue

            issue_text = f"{data.get('title', '')} {data.get('body', '')}".lower()
            issue_terms = set(self._tokenize(issue_text))

            # TF-IDF cosine similarity (simplified: sum of IDF for matched terms)
            score = sum(term_idf.get(t, 0) for t in query_terms if t in issue_terms)
            # Bonus for title matches
            title_lower = data.get("title", "").lower()
            title_match = sum(1 for t in query_terms if t in title_lower)
            score += title_match * 2.0

            if score > 0:
                scores.append((issue_id, score))

        scores.sort(key=lambda x: -x[1])
        results = []
        for issue_id, score in scores[:top_k]:
            data = self._issue_nodes[issue_id]
            data["issue_id"] = issue_id
            data["associated_files"] = self._issue_to_files.get(issue_id, [])[:20]
            data["associated_functions"] = self._issue_to_funcs.get(issue_id, [])[:20]
            results.append((data, round(score / max(1, len(query_terms)), 4)))

        return results

    # ------------------------------------------------------------------
    # Get files/functions for an issue or CVE
    # ------------------------------------------------------------------

    def get_issue_files(self, issue_id: str) -> List[str]:
        return self._issue_to_files.get(issue_id, [])

    def get_issue_functions(self, issue_id: str) -> List[str]:
        return self._issue_to_funcs.get(issue_id, [])

    def get_cve_issues(self, cve_id: str) -> List[dict]:
        """Get all issues for a CVE."""
        issues = []
        for src, dst, data in self.G.edges(data=True):
            if src == cve_id and data.get("edge_type") == "HAS_ISSUE":
                node_data = self._issue_nodes.get(dst, {})
                node_data["issue_id"] = dst
                issues.append(node_data)
        return issues

    def get_cve_files(self, cve_id: str) -> List[str]:
        """Get all files associated with a CVE's issues."""
        files: Set[str] = set()
        for issue in self.get_cve_issues(cve_id):
            files.update(self._issue_to_files.get(issue["issue_id"], []))
        return sorted(files)

    def get_cve_functions(self, cve_id: str) -> List[str]:
        """Get all functions associated with a CVE's issues."""
        funcs: Set[str] = set()
        for issue in self.get_cve_issues(cve_id):
            funcs.update(self._issue_to_funcs.get(issue["issue_id"], []))
        return sorted(funcs)

    # ------------------------------------------------------------------
    # Aggregated search — returns files ranked by relevance
    # ------------------------------------------------------------------

    def search_relevant_files(
        self, query: str, top_k: int = 20, language: str = ""
    ) -> List[Tuple[str, float]]:
        """Search for vulnerability-relevant files.

        Aggregates across similar issues and ranks by issue similarity * mention frequency.
        """
        similar = self.search_similar_issues(query, top_k=20, language=language)
        if not similar:
            return []

        file_scores: Dict[str, float] = defaultdict(float)
        for issue_data, issue_score in similar:
            issue_id = issue_data["issue_id"]
            for fpath in self._issue_to_files.get(issue_id, []):
                file_scores[fpath] += issue_score

        ranked = sorted(file_scores.items(), key=lambda x: -x[1])
        return ranked[:top_k]

    def search_relevant_functions(
        self, query: str, top_k: int = 20, language: str = ""
    ) -> List[Tuple[str, float]]:
        """Search for vulnerability-relevant functions."""
        similar = self.search_similar_issues(query, top_k=20, language=language)
        if not similar:
            return []

        func_scores: Dict[str, float] = defaultdict(float)
        for issue_data, issue_score in similar:
            issue_id = issue_data["issue_id"]
            for fname in self._issue_to_funcs.get(issue_id, []):
                func_scores[fname] += issue_score

        ranked = sorted(func_scores.items(), key=lambda x: -x[1])
        return ranked[:top_k]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Extract meaningful tokens from text."""
        text = text.lower()
        # Remove code blocks and URLs
        text = re.sub(r'```.*?```', ' ', text, flags=re.DOTALL)
        text = re.sub(r'https?://\S+', ' ', text)
        # Extract words
        tokens = re.findall(r'[a-z][a-z0-9_]{2,}', text)
        # Filter stopwords
        stopwords = {"the", "and", "for", "that", "this", "with", "from",
                     "when", "where", "which", "what", "have", "been", "was",
                     "not", "are", "but", "has", "had", "can", "all", "will"}
        return [t for t in tokens if t not in stopwords]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "issues": len(self._issue_nodes),
            "cves": len(self._cve_nodes),
            "files": len(self._file_to_issues),
            "functions": len(self._func_to_issues),
            "edges": self.G.number_of_edges(),
        }
