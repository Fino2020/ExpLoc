"""
Issue→Commit Linker — resolves GitHub issues to fix commits via git log.

Build process for each repo:
  1. Load history/history/{owner}_{project}.json → list of GitHub issues
  2. For each closed issue:
     a. closedByPullRequestsReferences → PR number → git log --all --grep='#<PR>' -1
     b. Fallback: scan git log for fix(es)? #<num>, resolve(s)? #<num>, close(s)? #<num>
  3. From matched commit: extract changed_files via git diff-tree,
     changed_functions via language-specific regex from diff
  4. Write to issue_links table

Anti-leakage: never reads dataset_with_changed_files_filter.json or Dataset/GT/.
Only uses history/history/ and git log.
"""

import json
import os
import re
import sqlite3
import subprocess
from typing import Dict, List, Optional, Set, Tuple

from shared.config import HISTORY_DIR, PROJECT_ROOT

# ---------------------------------------------------------------------------
# Patterns for commit message matching
# ---------------------------------------------------------------------------

FIX_PATTERNS = [
    re.compile(rf'(?:fix|close|resolve|address)(?:es|ed|s)?\s+#{re.escape(str(n))}\b', re.IGNORECASE)
    for n in range(1, 100000)  # compiled on demand, cached below
]

# Lazy-compiled pattern for arbitrary issue number
def _fix_pattern(num: int) -> re.Pattern:
    return re.compile(
        rf'(?:fix|close|resolve|address)(?:es|ed|s)?\s+#{num}\b', re.IGNORECASE
    )


# ---------------------------------------------------------------------------
# Function extraction from diffs (language-specific regex)
# ---------------------------------------------------------------------------

_FUNC_DEF_PATTERNS = {
    "c": re.compile(r'^[-+]\s*(?:static\s+)?(?:inline\s+)?(?:virtual\s+)?'
                    r'(?:[\w:*&<>\s]+\s+)?([\w_]+)\s*\([^)]*\)\s*\{', re.MULTILINE),
    "cpp": re.compile(r'^[-+]\s*(?:static\s+)?(?:inline\s+)?(?:virtual\s+)?'
                      r'(?:[\w:*&<>\s]+\s+)?([\w_]+)\s*\([^)]*\)\s*\{', re.MULTILINE),
    "python": re.compile(r'(?:async\s+)?def\s+([\w_]+)\s*\(', re.MULTILINE),
    "javascript": re.compile(r'(?:async\s+)?function\s+([\w_$]+)\s*\(|'
                             r'(?:const|let|var)\s+([\w_$]+)\s*=\s*(?:async\s+)?function\s*\(|'
                             r'(?:const|let|var)\s+([\w_$]+)\s*=\s*\([^)]*\)\s*=>', re.MULTILINE),
    "java": re.compile(r'(?:public|private|protected|static|\s)+'
                       r'(?:[\w<>\[\]]+\s+)?([\w_]+)\s*\([^)]*\)\s*\{', re.MULTILINE),
    "go": re.compile(r'\bfunc\s+(?:\([^)]*\)\s+)?([\w_]+)\s*\(', re.MULTILINE),
    "ruby": re.compile(r'\bdef\s+(?:self\.)?([\w_]+[!?]?)', re.MULTILINE),
    "rust": re.compile(r'\bfn\s+([\w_]+)\s*[<\(]', re.MULTILINE),
    "php": re.compile(r'(?:public\s+|private\s+|protected\s+|static\s+)*function\s+([\w_]+)\s*\(', re.IGNORECASE),
}

_CPP_KEYWORDS = {
    'if', 'while', 'for', 'switch', 'return', 'sizeof', 'case', 'default',
    'catch', 'else', 'do', 'goto', 'void', 'int', 'char', 'float', 'double',
    'bool', 'long', 'short', 'unsigned', 'signed', 'auto', 'extern', 'static',
    'const', 'volatile', 'register', 'enum', 'union', 'typedef', 'struct',
    'class', 'public', 'private', 'protected', 'virtual', 'inline', 'new',
    'delete', 'this', 'nullptr', 'true', 'false', 'NULL', 'throw', 'try',
    'signal', 'slot', 'namespace', 'using',
}


def _extract_changed_functions(patch: str, language: str) -> List[str]:
    """Extract changed function names from a unified diff patch."""
    funcs: Set[str] = set()
    lang = language.lower()

    # Try regex patterns for the specific language
    patterns = []
    if lang in _FUNC_DEF_PATTERNS:
        patterns.append(_FUNC_DEF_PATTERNS[lang])
    # C and C++ share patterns
    if lang == "c":
        pass  # already added
    elif lang == "cpp":
        pass  # already added

    for pat in patterns:
        for match in pat.finditer(patch):
            for g in match.groups():
                if g and len(g) >= 2:
                    if lang in ("c", "cpp") and g in _CPP_KEYWORDS:
                        continue
                    funcs.add(g)

    return list(funcs)


# ---------------------------------------------------------------------------
# File extension → language mapping
# ---------------------------------------------------------------------------

EXT_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php", ".phtml": "php",
}


def _detect_lang(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return EXT_TO_LANG.get(ext, "unknown")


# ---------------------------------------------------------------------------
# git log scanning
# ---------------------------------------------------------------------------

def _git_log_grep(repo_path: str, pattern: str, timeout: int = 30) -> Optional[str]:
    """Search git log for a pattern, return first matching commit SHA."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "log", "--all", "--pretty=format:%H",
             f"--grep={pattern}", "-1"],
            capture_output=True, text=True, timeout=timeout,
        )
        sha = result.stdout.strip()
        return sha if sha and len(sha) == 40 else None
    except Exception:
        return None


def _git_log_grep_extended(repo_path: str, issue_number: int, timeout: int = 60) -> List[str]:
    """Extended scan: find ALL commits referencing an issue number.

    Returns list of commit SHAs ordered by git log (most recent first).
    """
    shas = []
    try:
        # Primary: fix/close/resolve #num
        for verb in ("fix", "close", "resolve", "address"):
            pattern = f"{verb} # {issue_number}"
            sha = _git_log_grep(repo_path, pattern, timeout=timeout // 4)
            if sha:
                shas.append(sha)
                continue
            pattern = f"{verb} #{issue_number}"
            sha = _git_log_grep(repo_path, pattern, timeout=timeout // 4)
            if sha and sha not in shas:
                shas.append(sha)
        # Fallback: just the issue number
        if not shas:
            sha = _git_log_grep(repo_path, f"#{issue_number}", timeout=timeout // 2)
            if sha:
                shas.append(sha)
    except Exception:
        pass
    return shas


def _get_commit_info(repo_path: str, sha: str, timeout: int = 30) -> Optional[dict]:
    """Get commit message + date + changed files for a SHA."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "log", "--pretty=format:%H|%s|%an|%aI", "-n1", sha],
            capture_output=True, text=True, timeout=timeout,
        )
        parts = result.stdout.strip().split("|", 3)
        if len(parts) < 4:
            return None

        # Get changed files
        files_out = subprocess.run(
            ["git", "-C", repo_path, "diff-tree", "--no-commit-id",
             "--name-only", "-r", sha],
            capture_output=True, text=True, timeout=timeout,
        )
        changed_files = [f.strip() for f in files_out.stdout.split("\n") if f.strip()]

        # Get patch for function extraction
        patch_out = subprocess.run(
            ["git", "-C", repo_path, "diff-tree", "--no-commit-id", "-p", sha],
            capture_output=True, text=True, timeout=timeout,
        )

        # Extract changed functions
        changed_funcs: Set[str] = set()
        for fpath in changed_files:
            lang = _detect_lang(fpath)
            if lang != "unknown":
                funcs = _extract_changed_functions(patch_out.stdout[:10000], lang)
                changed_funcs.update(funcs)

        return {
            "sha": parts[0],
            "message": parts[1],
            "author": parts[2],
            "date": parts[3],
            "changed_files": changed_files,
            "changed_functions": list(changed_funcs)[:30],
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main linker
# ---------------------------------------------------------------------------

def link_issues(repo_path: str, owner: str, project: str, db_path: str,
                before_date: str = "") -> int:
    """Resolve GitHub issues to fix commits and populate issue_links table.

    Args:
        repo_path: path to git repository
        owner: GitHub owner/organization
        project: GitHub project name
        db_path: path to the SQLite RMS database
        before_date: if set, skip issues with closedAt >= before_date (anti-leakage).
                     The CVE's own issues (closed same day) are never skipped.

    Returns:
        Number of issues successfully linked to commits.
    """
    repo_key = f"{owner}_{project}"
    history_path = os.path.join(HISTORY_DIR, f"{repo_key}.json")

    if not os.path.exists(history_path):
        print(f"  No history file for {repo_key}")
        return 0

    if os.path.getsize(history_path) == 0:
        print(f"  Empty history file for {repo_key} (skipping issue link)")
        return 0

    with open(history_path, "r", encoding="utf-8") as f:
        issues = json.load(f)

    if not isinstance(issues, list):
        print(f"  Unexpected history format for {repo_key}")
        return 0

    print(f"  Loaded {len(issues)} issues from history for {repo_key}")

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")

    linked_count = 0
    for issue in issues:
        number = issue.get("number")
        if not number:
            continue

        title = issue.get("title", "")
        body = issue.get("body", "") or ""
        state = issue.get("state", "")
        created_at = issue.get("createdAt", "")
        closed_at = issue.get("closedAt", "") or issue.get("resolved_at", "")
        if before_date and closed_at and closed_at[:10] > before_date[:10]:
            continue  # skip issues resolved after CVE date (anti-leakage)
        labels = ",".join([l.get("name", "") for l in issue.get("labels", [])])

        commit_sha = ""
        pr_number = 0
        changed_files = ""
        changed_functions = ""

        # Strategy 1: closedByPullRequestsReferences → PR → merge commit
        pr_refs = issue.get("closedByPullRequestsReferences", [])
        if pr_refs:
            for pr_ref in pr_refs:
                pr_num = pr_ref.get("number")
                if not pr_num:
                    continue
                pr_number = pr_num
                # Search for merge commit referencing this PR
                sha = _git_log_grep(repo_path, f"'Merge pull request #{pr_num}'")
                if not sha:
                    sha = _git_log_grep(repo_path, f"'Merge #{pr_num}'")
                if not sha:
                    sha = _git_log_grep(repo_path, f"# {pr_num}")
                if sha:
                    commit_sha = sha
                    # Extract changed files/functions
                    info = _get_commit_info(repo_path, sha)
                    if info:
                        changed_files = ",".join(info["changed_files"])
                        changed_functions = ",".join(info["changed_functions"])
                    break

        # Strategy 2: git log scan for issue number
        if not commit_sha:
            shas = _git_log_grep_extended(repo_path, number)
            if shas:
                commit_sha = shas[0]  # most recent match
                info = _get_commit_info(repo_path, commit_sha)
                if info:
                    changed_files = ",".join(info["changed_files"])
                    changed_functions = ",".join(info["changed_functions"])

        # Strategy 3: keyword fallback (skip — too noisy, handled by BM25 in retriever)

        if commit_sha:
            linked_count += 1

        conn.execute(
            "INSERT OR REPLACE INTO issue_links VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                number, repo_key, title[:500], body[:5000], state,
                pr_number, commit_sha, changed_files, changed_functions,
                issue.get("closedAt", created_at), labels,
            ),
        )

        if linked_count % 50 == 0:
            conn.commit()
            print(f"    {linked_count} issues linked ...")

    conn.commit()
    conn.close()
    print(f"  Linked {linked_count}/{len(issues)} issues to commits")
    return linked_count


# ---------------------------------------------------------------------------
# Build helper: run build_rms + link_issues together
# ---------------------------------------------------------------------------

def build_rms_with_issues(
    repo_path: str, owner: str, project: str, output_db: str,
    max_commits: int = 500, top_hotspots: int = 30,
    before_date: str = "", fallback: str = "none",
) -> str:
    """Build RMS and populate issue_links in one call.

    Returns output_db path.
    """
    from step1_locator.memory_store import build_rms

    build_rms(
        repo_path=repo_path, output_db=output_db,
        max_commits=max_commits, top_hotspots=top_hotspots,
        before_date=before_date, fallback=fallback,
    )
    link_issues(
        repo_path=repo_path, owner=owner, project=project, db_path=output_db,
        before_date=before_date,
    )
    return output_db
