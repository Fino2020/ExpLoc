"""
Simple BM25 retriever over source code files — no llama_index dependency.

Indexes all source files in a repo, returns matching file chunks for a query.
"""

import json
import math
import os
import re
from collections import Counter
from typing import Dict, List, Optional


class BM25Retriever:
    """Minimal BM25 implementation over code files."""

    def __init__(self, k1: float = 1.2, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.documents: List[dict] = []          # [{file, start_line, end_line, text}]
        self.doc_lens: List[int] = []
        self.avgdl: float = 0.0
        self.idf: Dict[str, float] = {}
        self._built = False

    def index_repo(self, repo_path: str, max_file_size_kb: int = 500):
        """Walk repo_path, chunk files, build BM25 index."""
        self.documents = []
        for root, dirs, files in os.walk(repo_path):
            # Skip hidden and test directories
            dirs[:] = [d for d in dirs if not d.startswith(".")
                       and "test" not in d.lower()
                       and d not in ("node_modules", "vendor", "__pycache__",
                                     "build", "dist", ".git")]

            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, repo_path).replace("\\", "/")

                if self._is_test(rel_path):
                    continue

                ext = os.path.splitext(fname)[1].lower()
                if ext not in _SOURCE_EXTS:
                    continue

                try:
                    size_kb = os.path.getsize(fpath) / 1024
                    if size_kb > max_file_size_kb:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception:
                    continue

                if not content.strip():
                    continue

                # Chunk the file into blocks of ~50 lines
                lines = content.split("\n")
                chunk_size = 50
                for i in range(0, len(lines), chunk_size):
                    chunk_lines = lines[i:i + chunk_size]
                    chunk_text = "\n".join(chunk_lines)
                    self.documents.append({
                        "file": rel_path,
                        "start_line": i + 1,
                        "end_line": min(i + chunk_size, len(lines)),
                        "text": chunk_text,
                    })

        self._build_index()

    def _is_test(self, rel_path: str) -> bool:
        parts = re.split(r"[ /_\-]", rel_path.lower())
        return any(p.startswith("test") or p == "tests" for p in parts)

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenizer: lowercase, split on non-alphanumeric."""
        text = text.lower()
        tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text)
        return [t for t in tokens if len(t) > 1]

    def _build_index(self):
        self.doc_lens = []
        doc_term_freqs = []
        df = Counter()  # document frequency

        for doc in self.documents:
            tokens = self._tokenize(doc["text"])
            self.doc_lens.append(len(tokens))
            tf = Counter(tokens)
            doc_term_freqs.append(tf)
            for term in tf:
                df[term] += 1

        N = len(self.documents)
        self.avgdl = sum(self.doc_lens) / max(N, 1)

        # Compute IDF
        self.idf = {}
        for term, freq in df.items():
            self.idf[term] = math.log((N - freq + 0.5) / (freq + 0.5) + 1.0)

        # Store pre-computed TF for scoring
        self._doc_tfs = doc_term_freqs
        self._built = True

    def retrieve(self, query: str, similarity_top_k: int = 10,
                 include_files: Optional[List[str]] = None) -> List[dict]:
        """Return top-k results as list of {file, start_line, end_line, score, text}."""
        if not self._built:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        scores = []
        for idx, doc in enumerate(self.documents):
            if include_files and doc["file"] not in include_files:
                continue
            score = self._score(query_tokens, idx)
            if score > 0:
                scores.append((score, idx))

        scores.sort(key=lambda x: x[0], reverse=True)
        results = []
        for score, idx in scores[:similarity_top_k]:
            doc = self.documents[idx]
            results.append({
                "file": doc["file"],
                "start_line": doc["start_line"],
                "end_line": doc["end_line"],
                "score": score,
                "text": doc["text"],
            })
        return results

    def _score(self, query_tokens: List[str], doc_idx: int) -> float:
        score = 0.0
        doc_len = self.doc_lens[doc_idx]
        tf = self._doc_tfs[doc_idx]
        for token in query_tokens:
            if token not in self.idf:
                continue
            token_tf = tf.get(token, 0)
            if token_tf == 0:
                continue
            numerator = token_tf * (self.k1 + 1)
            denominator = token_tf + self.k1 * (1 - self.b + self.b * doc_len / max(self.avgdl, 1))
            score += self.idf[token] * numerator / denominator
        return score


    def save(self, path: str):
        """Persist BM25 index to JSON file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {
            "k1": self.k1,
            "b": self.b,
            "documents": self.documents,
            "doc_lens": self.doc_lens,
            "avgdl": self.avgdl,
            "_doc_tfs": {str(k): dict(v) for k, v in enumerate(self._doc_tfs)},
            "idf": self.idf,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> "BM25Retriever":
        """Load BM25 index from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ret = cls(k1=data["k1"], b=data["b"])
        ret.documents = data["documents"]
        ret.doc_lens = data["doc_lens"]
        ret.avgdl = data["avgdl"]
        ret.idf = data["idf"]
        ret._doc_tfs = [Counter(v) for k, v in sorted(
            [(int(k), v) for k, v in data["_doc_tfs"].items()], key=lambda x: x[0])]
        ret._built = True
        return ret


_SOURCE_EXTS = {
    ".py", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh",
    ".java", ".kt", ".kts", ".scala",
    ".js", ".ts", ".jsx", ".tsx", ".mjs",
    ".go", ".rs", ".rb", ".php", ".swift",
    ".cs", ".vb", ".pl", ".pm",
}
