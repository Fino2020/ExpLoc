#!/usr/bin/env python3
"""
RLocator Baseline — CodeBERT Semantic Similarity Ranking.

Replicates the core representation-learning component of RLocator (ICSE 2022):
  1. Embed the CVE report (issue title + body) with CodeBERT
  2. Embed each source file in the repo with CodeBERT
  3. Rank files by cosine similarity between report and file embeddings

This is the semantic signal that RLocator's A2C agent consumes as observations.
Without the trained RL policy (project-specific), similarity ranking is the
closest achievable baseline for an arbitrary multi-language CVE dataset.

Ref: /mnt/d/Desktop/Replication/RLocator.pdf
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import numpy as np
import torch
from tqdm import tqdm
from transformers import AutoModel, AutoTokenizer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MANIFEST_PATH = "Dataset/dataset_with_changed_files_filter.json"
OUTPUT_DIR = "Results/Localization/rlocator_baseline"
REPO_BASE = "/mnt/e/Desktop/Localization_Repo/Localization_Repo"

MODEL_NAME = "microsoft/codebert-base"
MAX_TOKENS = 512
BATCH_SIZE = 16

# Source file extensions per language
SRC_EXTS = {
    "c", "h", "cpp", "cxx", "cc", "hpp", "hh",  # C/C++
    "java",  # Java
    "js", "jsx", "mjs", "ts", "tsx",  # JavaScript/TypeScript
    "py", "pyx", "pxd",  # Python
    "php", "phtml",  # PHP
    "go",  # Go
    "rs",  # Rust
    "rb",  # Ruby
    "pl", "pm",  # Perl
    "swift",  # Swift
    "kt", "kts",  # Kotlin
    "scala",  # Scala
    "cs",  # C#
    "sql", "psql",  # SQL
    "sh", "bash", "zsh",  # Shell
    "cmake", "make", "mk",  # Build
    "xml", "json", "yaml", "yml", "toml", "ini", "cfg",  # Config (lower priority)
}

# Directories to exclude
EXCLUDE_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__",
    ".svn", ".hg", "build", "dist", "target",
    "test", "tests", "spec", "specs", "example", "examples",
    "doc", "docs", "documentation",
    "third_party", "thirdparty", "external",
    "bower_components", "jspm_packages",
}

# Files to exclude by name pattern
EXCLUDE_PATTERNS = [
    r"\.min\.(js|css)$",  # Minified files
    r"\.bundle\.(js|css)$",  # Bundled files
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"\.eslintrc",
    r"\.prettierrc",
    r"tsconfig",
    r"\.gitignore",
    r"\.dockerignore",
    r"Dockerfile",
    r"Makefile$",
    r"\.gradle/",
    r"\.mvn/",
    r"\.png$", r"\.jpg$", r"\.jpeg$", r"\.gif$", r"\.ico$", r"\.svg$",
    r"\.pdf$", r"\.doc$", r"\.docx$",
    r"\.zip$", r"\.tar$", r"\.gz$", r"\.bz2$",
    r"\.exe$", r"\.dll$", r"\.so$", r"\.a$", r"\.o$",
    r"\.pyc$", r"\.class$",
    r"\.ttf$", r"\.woff", r"\.eot$",
    r"\.map$",  # Source maps
    r"LICENSE", r"COPYING",
    r"CHANGELOG", r"CHANGES",
    r"AUTHORS", r"CONTRIBUTORS",
    r"\.po$", r"\.mo$", r"\.pot$",  # Translation files
]

MAX_FILE_SIZE = 1_000_000  # 1 MB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_source_file(filepath: str) -> bool:
    """Check if a file is a source code file."""
    ext = os.path.splitext(filepath)[1].lstrip(".").lower()
    if ext not in SRC_EXTS:
        return False
    basename = os.path.basename(filepath)
    for pat in EXCLUDE_PATTERNS:
        if re.search(pat, basename) or re.search(pat, filepath):
            return False
    return True


def _is_excluded_dir(path: str) -> bool:
    """Check if a path component is an excluded directory."""
    parts = set(os.path.normpath(path).split(os.sep))
    return bool(parts & EXCLUDE_DIRS)


def list_source_files(repo_path: str) -> list:
    """Walk a repo and return relative paths of all source files."""
    files = []
    for root, dirs, filenames in os.walk(repo_path, topdown=True):
        # Filter excluded directories in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fname in filenames:
            full = os.path.join(root, fname)
            try:
                fsize = os.path.getsize(full)
                if fsize > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            rel = os.path.relpath(full, repo_path)
            if _is_source_file(rel) and not _is_excluded_dir(rel):
                files.append(rel)
    return files


def read_file_content(repo_path: str, rel_path: str) -> str | None:
    """Read a file's text content, with encoding fallback."""
    full = os.path.join(repo_path, rel_path)
    for enc in ("utf-8", "latin-1", "cp1252", "iso-8859-1"):
        try:
            with open(full, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, FileNotFoundError):
            continue
    return None


def extract_function_names(content: str, language: str) -> list:
    """Simple regex-based function name extraction for the top files."""
    patterns = {
        "c":          [r"(?:static\s+)?(?:\w+[\s*]+)+(\w+)\s*\([^)]*\)\s*{"],
        "java":       [r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws[^{]*)?\{"],
        "javascript": [r"function\s+(\w+)\s*\([^)]*\)",
                       r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>",
                       r"(?:async\s+)?(\w+)\s*\([^)]*\)\s*{"],
        "python":     [r"def\s+(\w+)\s*\([^)]*\)"],
        "php":        [r"function\s+(\w+)\s*\([^)]*\)"],
    }
    pats = patterns.get(language, patterns["c"])
    names = []
    for pat in pats:
        matches = re.findall(pat, content, re.MULTILINE)
        names.extend(matches)
    return list(dict.fromkeys(names))  # dedup, preserve order


def build_report(cve_entry: dict) -> str:
    """Build a natural-language report from the CVE issue data."""
    issues = cve_entry.get("issue_list", [])
    if not issues:
        return cve_entry.get("cve_id", "")
    main_issue = issues[0]
    title = main_issue.get("title", "")
    body = main_issue.get("body", "")
    if body:
        # Strip markdown code blocks for cleaner embedding
        body = re.sub(r"```[\s\S]*?```", " [CODE] ", body)
    report = f"{title}\n{body}"
    if len(report) > 8000:
        report = report[:8000]
    return report.strip()


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class CodeBERTRanker:
    """CodeBERT-based semantic similarity ranker."""

    def __init__(self, model_name: str = MODEL_NAME, device: str = "cpu"):
        self.device = device
        print(f"Loading {model_name} on {device}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name).to(device)
        self.model.eval()

    @torch.no_grad()
    def embed(self, texts: list[str]) -> np.ndarray:
        """Mean-pool CodeBERT embeddings for a list of texts."""
        embeddings = []
        for i in range(0, len(texts), BATCH_SIZE):
            batch = texts[i:i + BATCH_SIZE]
            tokens = self.tokenizer(
                batch, max_length=MAX_TOKENS, truncation=True,
                padding=True, return_tensors="pt",
            ).to(self.device)
            outputs = self.model(**tokens)
            hidden = outputs.last_hidden_state  # (B, seq, 768)
            mask = tokens["attention_mask"].unsqueeze(-1).float()
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
            embeddings.append(pooled.cpu().numpy())
        return np.concatenate(embeddings, axis=0)

    def rank(
            self, report_text: str, file_paths: list[str],
            repo_path: str
    ) -> list[tuple[str, float]]:
        """Rank files by cosine similarity to the report."""
        if not file_paths:
            return []

        # Read file contents
        file_texts = []
        valid_paths = []
        for fp in file_paths:
            content = read_file_content(repo_path, fp)
            if content and len(content.strip()) > 10:
                file_texts.append(content)
                valid_paths.append(fp)

        if not valid_paths:
            return []

        # Embed report
        report_emb = self.embed([report_text])[0]
        report_norm = report_emb / (np.linalg.norm(report_emb) + 1e-12)

        # Embed files
        file_embs = self.embed(file_texts)
        file_norms = np.linalg.norm(file_embs, axis=1, keepdims=True) + 1e-12
        file_embs_normed = file_embs / file_norms

        # Cosine similarity
        sims = np.dot(file_embs_normed, report_norm)

        # Rank
        ranked = sorted(
            zip(valid_paths, sims.tolist()),
            key=lambda x: x[1], reverse=True,
        )
        return ranked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_baseline(
        manifest_path: str = MANIFEST_PATH,
        output_dir: str = OUTPUT_DIR,
        repo_base: str = REPO_BASE,
        limit: int = 0,
        skip: int = 0,
        project_filter: str | None = None,
        resume: bool = True,
):
    """Run RLocator baseline on all CVEs in the manifest."""
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    total = len(manifest)
    print(f"Dataset: {total} CVEs from {manifest_path}")
    print(f"Output:  {output_dir}")
    print(f"Repos:   {repo_base}")
    print()

    # Load model
    device = "cuda:0" if torch.cuda.is_available() else "cpu"
    ranker = CodeBERTRanker(device=device)

    os.makedirs(output_dir, exist_ok=True)

    # Determine range
    if limit and limit > 0:
        manifest = manifest[:limit]
    if skip > 0:
        manifest = manifest[skip:]

    processed = 0
    skipped_existing = 0
    skipped_no_repo = 0
    skipped_no_files = 0
    errors = []

    pbar = tqdm(enumerate(manifest, start=(skip + 1) if skip else 1), total=len(manifest))

    for idx, cve in pbar:
        cve_id = cve["cve_id"]

        # Filter by project if specified
        if project_filter:
            proj = f"{cve.get('owner', '')}/{cve.get('project', '')}"
            if project_filter.lower() not in proj.lower():
                continue

        # Resume: skip if output already exists
        out_path = os.path.join(output_dir, cve_id, "result.json")
        if resume and os.path.exists(out_path):
            skipped_existing += 1
            pbar.set_postfix({ "proc": processed, "skip_exist": skipped_existing })
            continue

        # Find repo
        repo_path = cve.get("repo_path", "")
        if not repo_path or not os.path.isdir(repo_path):
            # Try repo_base lookup
            owner = cve.get("owner", "")
            project = cve.get("project", "")
            if owner and project:
                repo_path = os.path.join(repo_base, cve_id, owner, project)
            if not os.path.isdir(repo_path):
                skipped_no_repo += 1
                continue

        try:
            # Build report
            report = build_report(cve)
            if not report:
                skipped_no_files += 1
                continue

            # List source files
            src_files = list_source_files(repo_path)
            if not src_files:
                skipped_no_files += 1
                continue

            # Rank files
            t0 = time.time()
            ranked_files = ranker.rank(report, src_files, repo_path)
            elapsed = time.time() - t0

            if not ranked_files:
                skipped_no_files += 1
                continue

            # Extract function names from top files for function-level predictions
            language = cve.get("language", "c")
            func_names = []
            for fp, _ in ranked_files[:30]:
                content = read_file_content(repo_path, fp)
                if content:
                    func_names.extend(extract_function_names(content, language))

            # Deduplicate while preserving order
            seen = set()
            func_names = [f for f in func_names if not (f in seen or seen.add(f))]

            # Build result.json
            result = {
                "cve_id":          cve_id,
                "owner":           cve.get("owner", ""),
                "project":         cve.get("project", ""),
                "language":        cve.get("language", ""),
                "issue_title":     (cve.get("issue_list", [{ }]) or [{ }])[0].get("title", ""),
                "issue_body":      (cve.get("issue_list", [{ }]) or [{ }])[0].get("body", "")[:2000],
                "elapsed_seconds": round(elapsed, 1),
                "baseline":        "RLocator-CodeBERT-Similarity",
                "pipeline":        {
                    "_ranked_files":     [[fp, round(score, 6)] for fp, score in ranked_files],
                    "_ranked_functions": [[fn, 1.0] for fn in func_names[:100]],
                },
            }

            # Save
            cve_out_dir = os.path.join(output_dir, cve_id)
            os.makedirs(cve_out_dir, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            processed += 1
            pbar.set_postfix(
                {
                    "proc":  processed,
                    "files": len(ranked_files),
                    "sec":   f"{elapsed:.1f}",
                }
            )

        except Exception as e:
            errors.append((cve_id, str(e)))
            pbar.set_postfix({ "err": cve_id })
            continue

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  RLocator Baseline — Complete")
    print(f"{'=' * 60}")
    print(f"  Processed:         {processed}")
    print(f"  Skipped (existing): {skipped_existing}")
    print(f"  Skipped (no repo):  {skipped_no_repo}")
    print(f"  Skipped (no files): {skipped_no_files}")
    print(f"  Errors:             {len(errors)}")
    if errors:
        for cid, msg in errors[:10]:
            print(f"    {cid}: {msg}")
    print(f"\n  Results saved to: {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="RLocator Baseline — CodeBERT similarity ranking for CVE localization"
    )
    parser.add_argument(
        "--manifest", default=MANIFEST_PATH,
        help="Path to full_manifest.json"
    )
    parser.add_argument(
        "--output", default=OUTPUT_DIR,
        help="Output directory for result.json files"
    )
    parser.add_argument(
        "--repo-base", default=REPO_BASE,
        help="Base path for cloned repos"
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Process only first N CVEs (0 = all)"
    )
    parser.add_argument(
        "--skip", type=int, default=0,
        help="Skip first N CVEs"
    )
    parser.add_argument(
        "--project", default=None,
        help="Filter by project name (owner/project substring)"
    )
    parser.add_argument(
        "--no-resume", action="store_true",
        help="Do not skip existing results"
    )
    args = parser.parse_args()

    run_baseline(
        manifest_path=args.manifest,
        output_dir=args.output,
        repo_base=args.repo_base,
        limit=args.limit,
        skip=args.skip,
        project_filter=args.project,
        resume=not args.no_resume,
    )
