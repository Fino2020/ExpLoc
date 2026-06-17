"""
Build Knowledge Graph from full_manifest.json.

KG Structure (matching RepoMem paper):
  Nodes:
    - CVE: vulnerability report (cve_id, title, body, language)
    - Issue: GitHub issue (issue_id, title, body, labels)
    - File: source file path (path, language)
    - Function: function name (name, file_path)

  Edges:
    - HAS_ISSUE: CVE → Issue
    - MENTIONS_FILE: Issue → File (extracted from issue text)
    - MENTIONS_FUNCTION: Issue → Function (extracted from issue text)
    - RELATED_TO: File → Function (function belongs to file)

Usage:
  python3 build_kg.py
Output:
  RepoMem/mem_construction/repo_mem_kg.graphml
  RepoMem/mem_construction/kg_index.json    (inverted index for fast lookup)
"""

import json
import os
import re
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple

import networkx as nx

# XML 1.0 invalid characters (only 0x09, 0x0A, 0x0D are allowed)
_INVALID_XML_RE = re.compile(
    '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff﷐-﷯'
    '￾￿\U0001fffe\U0001ffff\U0002fffe\U0002ffff\U0003fffe'
    '\U0003ffff\U0004fffe\U0004ffff\U0005fffe\U0005ffff\U0006fffe'
    '\U0006ffff\U0007fffe\U0007ffff\U0008fffe\U0008ffff\U0009fffe'
    '\U0009ffff\U000afffe\U000affff\U000bfffe\U000bffff\U000cfffe'
    '\U000cffff\U000dfffe\U000dffff\U000efffe\U000effff\U000ffffe'
    '\U000fffff\U0010fffe\U0010ffff]'
)


def _sanitize_xml(text: str) -> str:
    """Remove characters invalid in XML 1.0."""
    if not text:
        return ""
    return _INVALID_XML_RE.sub(' ', text)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MANIFEST_PATH = os.path.join(BASE_DIR, "Dataset", "full_manifest.json")
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
KG_PATH = os.path.join(OUTPUT_DIR, "repo_mem_kg.graphml")
INDEX_PATH = os.path.join(OUTPUT_DIR, "kg_index.json")

# ---------------------------------------------------------------------------
# File/Function name extraction from issue text
# ---------------------------------------------------------------------------

# Common file extensions for each language
LANG_EXTENSIONS = {
    "c": [r"\.c\b", r"\.h\b", r"\.cpp\b", r"\.hpp\b", r"\.cc\b"],
    "cpp": [r"\.cpp\b", r"\.hpp\b", r"\.cc\b", r"\.cxx\b", r"\.c\b", r"\.h\b"],
    "javascript": [r"\.js\b", r"\.jsx\b", r"\.ts\b", r"\.tsx\b", r"\.mjs\b", r"\.vue\b"],
    "python": [r"\.py\b", r"\.pyx\b", r"\.pxd\b"],
    "java": [r"\.java\b", r"\.kt\b", r"\.scala\b"],
    "php": [r"\.php\b", r"\.phtml\b"],
    "ruby": [r"\.rb\b", r"\.erb\b"],
    "go": [r"\.go\b"],
    "rust": [r"\.rs\b"],
    "perl": [r"\.pl\b", r"\.pm\b"],
    "ocaml": [r"\.ml\b", r"\.mli\b"],
}

# Patterns for file path mentions in text
FILE_PATH_PATTERNS = [
    # Absolute/relative paths
    re.compile(r'(?:^|\s|\()([\w._/-]+\.(?:c|h|cpp|hpp|cc|cxx|js|jsx|ts|tsx|mjs|vue|py|pyx|java|kt|scala|php|phtml|rb|erb|go|rs|pl|pm|ml|mli))(?:\s|$|[:\),.;])', re.IGNORECASE),
    # Paths after "in", "file", "at"
    re.compile(r'(?:in|file|at)\s+[`"\']?([\w._/-]+\.\w{1,4})[`"\']?', re.IGNORECASE),
    # Backtick-quoted paths
    re.compile(r'`([\w._/-]+\.\w{1,4})`', re.IGNORECASE),
]

# Patterns for function name mentions
FUNC_NAME_PATTERNS = [
    # snake_case functions
    re.compile(r'\b([a-z][a-z0-9]*(?:_[a-z0-9]+){1,})\s*\(', re.IGNORECASE),
    # camelCase functions
    re.compile(r'\b([a-z][a-zA-Z0-9]{4,})\s*\(', re.IGNORECASE),
    # PascalCase functions
    re.compile(r'\b([A-Z][a-zA-Z0-9]{4,})\s*\(', re.IGNORECASE),
    # C-style function declarations: type name(...)
    re.compile(r'(?:void|int|char|float|double|bool|long|static|const|struct|enum|size_t|ssize_t|uint\w*|int\w+)\s+(\w+)\s*\(', re.IGNORECASE),
    # After "function" keyword
    re.compile(r'function\s+(\w+)\s*\(', re.IGNORECASE),
    # After "def" (Python)
    re.compile(r'def\s+(\w+)\s*\(', re.IGNORECASE),
]

# Common non-function names to filter out
NON_FUNC_WORDS = {
    "if", "else", "for", "while", "switch", "case", "return", "break",
    "continue", "sizeof", "typeof", "catch", "throw", "throws", "finally",
    "import", "export", "require", "include", "namespace", "using",
    "public", "private", "protected", "class", "interface", "extends",
    "implements", "this", "super", "new", "try", "except",
    "assert", "print", "echo", "exit", "die",
}

def _extract_files_from_text(text: str, language: str) -> Set[str]:
    """Extract file path mentions from issue text."""
    files: Set[str] = set()
    for pattern in FILE_PATH_PATTERNS:
        for match in pattern.finditer(text):
            path = match.group(1)
            # Basic validation
            path = path.strip("`\"'()[]{}")
            if "." in path and 3 < len(path) < 200:
                # Check if extension matches language
                ext_match = re.search(r'\.(\w+)$', path)
                if ext_match:
                    files.add(path)
    return files


def _extract_functions_from_text(text: str) -> Set[str]:
    """Extract function name mentions from issue text."""
    funcs: Set[str] = set()
    for pattern in FUNC_NAME_PATTERNS:
        for match in pattern.finditer(text):
            name = match.group(1)
            name_lower = name.lower()
            if name_lower not in NON_FUNC_WORDS and len(name) >= 3:
                funcs.add(name)
    return funcs


# ---------------------------------------------------------------------------
# KG Construction
# ---------------------------------------------------------------------------

def build_kg(manifest_path: str = MANIFEST_PATH) -> nx.DiGraph:
    """Build the RepoMem Knowledge Graph from the dataset manifest."""
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    G = nx.DiGraph()
    file_freq: Dict[str, int] = defaultdict(int)
    func_freq: Dict[str, int] = defaultdict(int)
    index_data: Dict[str, dict] = {}

    print(f"Building KG from {len(manifest)} CVEs...")

    for entry in manifest:
        cve_id = entry["cve_id"]
        language = entry.get("language", "unknown")
        cve_title = ""
        cve_body = ""

        # CVE node
        G.add_node(cve_id, node_type="CVE", language=language)

        for issue in entry.get("issue_list", []):
            issue_id = f"{issue.get('repo', 'unknown')}#{issue.get('id', 0)}"
            title = issue.get("title", "")
            body = issue.get("body", "") or ""
            labels = [l.get("name", "") for l in issue.get("labels", [])]

            if not cve_title:
                cve_title = title
            if not cve_body:
                cve_body = body

            # Collect all issue text (title + body + comments)
            all_text = f"{title}\n{body}"
            for event in issue.get("events", []):
                event_body = event.get("body", "")
                if event_body:
                    all_text += f"\n{event_body}"

            # Issue node
            G.add_node(
                issue_id,
                node_type="Issue",
                title=_sanitize_xml(title[:500]),
                body=_sanitize_xml(body[:2000]),
                labels=_sanitize_xml(json.dumps(labels)),
                language=language,
            )
            G.add_edge(cve_id, issue_id, edge_type="HAS_ISSUE")

            # Extract files from text
            files = _extract_files_from_text(all_text, language)
            # Also extract from GT changed_files if available
            for cf in entry.get("changed_files", []) or []:
                files.add(cf)

            for fpath in files:
                # Normalize path
                fpath = fpath.strip().lstrip("./")
                if len(fpath) < 3 or len(fpath) > 200:
                    continue

                if not G.has_node(fpath):
                    G.add_node(fpath, node_type="File", language=language)
                G.add_edge(issue_id, fpath, edge_type="MENTIONS_FILE")
                file_freq[fpath] += 1

            # Extract functions from text
            funcs = _extract_functions_from_text(all_text)
            # Also extract from GT changed_functions if available
            for cf in entry.get("changed_functions", []) or []:
                if cf.lower() not in NON_FUNC_WORDS:
                    funcs.add(cf)

            for fname in funcs:
                if not G.has_node(fname):
                    G.add_node(fname, node_type="Function", language=language)
                G.add_edge(issue_id, fname, edge_type="MENTIONS_FUNCTION")
                func_freq[fname] += 1

        # Update CVE node with full info
        if cve_title:
            G.nodes[cve_id]["title"] = _sanitize_xml(cve_title[:500])
            G.nodes[cve_id]["body"] = _sanitize_xml(cve_body[:2000])

        # Build index entry
        index_data[cve_id] = {
            "cve_id": cve_id,
            "language": language,
            "title": cve_title[:500],
            "body": cve_body[:2000],
            "files": list(files) if "files" in dir() else [],
            "functions": list(funcs) if "funcs" in dir() else [],
        }

    # Store file/function frequencies as node attributes
    for fpath, count in file_freq.items():
        if G.has_node(fpath):
            G.nodes[fpath]["mention_count"] = count

    for fname, count in func_freq.items():
        if G.has_node(fname):
            G.nodes[fname]["mention_count"] = count

    # Save KG
    nx.write_graphml(G, KG_PATH)
    print(f"KG saved: {KG_PATH}")
    print(f"  Nodes: {G.number_of_nodes()} ({dict(Counter(d['node_type'] for _, d in G.nodes(data=True)) | {'total': 0})})")
    counts = defaultdict(int)
    for _, d in G.nodes(data=True):
        counts[d.get("node_type", "unknown")] += 1
    for ntype, cnt in sorted(counts.items()):
        print(f"    {ntype}: {cnt}")
    print(f"  Edges: {G.number_of_edges()}")

    # Save index
    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(index_data, f, indent=2, ensure_ascii=False)
    print(f"Index saved: {INDEX_PATH}")

    return G


if __name__ == "__main__":
    from collections import Counter
    build_kg()
