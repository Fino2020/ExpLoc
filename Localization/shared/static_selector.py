"""
Adaptive ICFG Selector — picks the best available ICFG source for a CVE.

Evaluates CodeQL, ScubaTrace tree-sitter, and Joern CPG sources.
Supports strategies: auto, codeql_first, joern_first, scubatrace_first,
best_coverage, fuse, merge.

Adapted from Explainable_Localization/static_selector.py.
"""

import csv
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

from shared.config import ICFG_DIR, SCUBA_RESULTS_DIR

SOURCE_CODEQL = "codeql"
SOURCE_SCUBATRACE = "scubatrace"
SOURCE_JOERN = "joern_cpg"
SOURCE_MERGED = "merged"
SOURCE_FUSED = "fused"


@dataclass
class IcfgSource:
    source_type: str
    path: str
    file_count: int = 0
    function_count: int = 0
    edge_count: int = 0
    file_coverage: float = 0.0
    func_coverage: float = 0.0


@dataclass
class SelectionResult:
    selected_path: Optional[str]
    source_type: Optional[str]
    selection_reason: str
    all_sources: List[dict] = field(default_factory=list)
    file_coverage: float = 0.0
    func_coverage: float = 0.0


# ---------------------------------------------------------------------------
# ICFG Index — fast CSV stats without full graph parsing
# ---------------------------------------------------------------------------

class IcfgIndex:
    """Fast lookup for ICFG file/function coverage."""

    def __init__(self, csv_path: str):
        self.files: set = set()
        self.functions: set = set()
        self.total_edges = 0
        if csv_path and os.path.exists(csv_path):
            self._load(csv_path)

    MAX_INDEX_SIZE_MB = 200  # skip reading files larger than this
    MAX_INDEX_ROWS = 200_000  # sample at most this many rows for stats

    def _load(self, csv_path: str):
        try:
            file_size = os.path.getsize(csv_path)
        except OSError:
            return

        size_mb = file_size / (1024 * 1024)
        if size_mb > self.MAX_INDEX_SIZE_MB:
            # Estimate from file size — too large to read for indexing
            avg_row_bytes = max(file_size / max(self.MAX_INDEX_ROWS, 1), 30)
            self.total_edges = int(file_size / avg_row_bytes)
            return

        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = [h.strip().lower().strip('"') for h in next(reader, [])]
                if not header:
                    return
                for row in reader:
                    if self.total_edges >= self.MAX_INDEX_ROWS:
                        break  # enough for stats
                    if len(row) < 2:
                        continue
                    file_path = row[0].strip().strip('"')
                    func_name = row[1].strip().strip('"')
                    self.files.add(file_path)
                    if func_name:
                        self.functions.add(func_name)
                    self.total_edges += 1
        except Exception:
            pass

    def find_file_fuzzy(self, file_path: str) -> Optional[str]:
        """Fuzzy-match a file path against the ICFG index."""
        if file_path in self.files:
            return file_path
        norm_gt = file_path.replace('\\', '/')
        gt_parts = norm_gt.split('/')
        gt_bn = gt_parts[-1] if gt_parts else ""

        for f in self.files:
            norm_f = f.replace('\\', '/')
            if norm_f.endswith(norm_gt) or norm_gt.endswith(norm_f):
                return f

        for depth in (3, 2):
            if len(gt_parts) >= depth:
                gt_suffix = '/'.join(gt_parts[-depth:])
                for f in self.files:
                    norm_f = f.replace('\\', '/')
                    f_parts = norm_f.split('/')
                    if len(f_parts) >= depth and '/'.join(f_parts[-depth:]) == gt_suffix:
                        return f

        parent = gt_parts[-2] if len(gt_parts) >= 2 else ""
        for f in self.files:
            norm_f = f.replace('\\', '/')
            f_parts = norm_f.split('/')
            if len(f_parts) >= 2 and f_parts[-1] == gt_bn and f_parts[-2] == parent:
                return f

        for f in self.files:
            if f.replace('\\', '/').endswith('/' + gt_bn):
                return f
        return None

    def has_function(self, func_name: str) -> bool:
        """Check if a function exists (exact or fuzzy) in the ICFG."""
        if func_name in self.functions:
            return True
        for fname in self.functions:
            if func_name.lower() in fname.lower() or fname.lower() in func_name.lower():
                return True
        return False


# ---------------------------------------------------------------------------
# Source discovery
# ---------------------------------------------------------------------------

def _get_csv_stats(csv_path: str) -> dict:
    """Get basic stats from an ICFG CSV file."""
    if not csv_path or not os.path.exists(csv_path):
        return {"files": 0, "functions": 0, "edges": 0}
    idx = IcfgIndex(csv_path)
    return {"files": len(idx.files), "functions": len(idx.functions), "edges": idx.total_edges}


def find_available_sources(cve_id: str,
                           icfg_base_dir: str = ICFG_DIR,
                           scuba_results_dir: str = SCUBA_RESULTS_DIR) -> List[IcfgSource]:
    """Find all available ICFG sources for a given CVE."""
    sources = []

    # CodeQL
    db_path = os.path.join(icfg_base_dir, cve_id, "icfg_icfg_db.csv")
    raw_path = os.path.join(icfg_base_dir, cve_id, "icfg_icfg.csv")
    cq_path = db_path if os.path.exists(db_path) else (raw_path if os.path.exists(raw_path) else None)
    if cq_path:
        stats = _get_csv_stats(cq_path)
        sources.append(IcfgSource(
            source_type=SOURCE_CODEQL, path=cq_path,
            file_count=stats["files"], function_count=stats["functions"],
            edge_count=stats["edges"],
        ))

    # ScubaTrace tree-sitter
    st_path = os.path.join(scuba_results_dir, cve_id, "icfg_scubatrace.csv")
    if os.path.exists(st_path):
        stats = _get_csv_stats(st_path)
        sources.append(IcfgSource(
            source_type=SOURCE_SCUBATRACE, path=st_path,
            file_count=stats["files"], function_count=stats["functions"],
            edge_count=stats["edges"],
        ))

    # Joern CPG
    joern_path = os.path.join(scuba_results_dir, cve_id, "icfg_joern.csv")
    if os.path.exists(joern_path):
        stats = _get_csv_stats(joern_path)
        sources.append(IcfgSource(
            source_type=SOURCE_JOERN, path=joern_path,
            file_count=stats["files"], function_count=stats["functions"],
            edge_count=stats["edges"],
        ))

    return sources


# ---------------------------------------------------------------------------
# Coverage computation (requires GT — evaluation only, NOT prediction)
# ---------------------------------------------------------------------------

def compute_coverage_for_sources(sources: List[IcfgSource],
                                 gt_files: List[str],
                                 gt_functions: List[str]) -> None:
    """Compute file/function coverage for each source against GT (mutates sources)."""
    for src in sources:
        if not src.path:
            continue
        idx = IcfgIndex(src.path)
        files_found = sum(1 for gf in gt_files if idx.find_file_fuzzy(gf))
        funcs_found = sum(1 for gf in gt_functions if idx.has_function(gf))
        src.file_coverage = files_found / len(gt_files) if gt_files else 0.0
        src.func_coverage = funcs_found / len(gt_functions) if gt_functions else 0.0


# ---------------------------------------------------------------------------
# Main selector
# ---------------------------------------------------------------------------

def select_best_icfg(cve_id: str,
                     language: str = "",
                     gt_files: Optional[List[str]] = None,
                     gt_functions: Optional[List[str]] = None,
                     icfg_base_dir: str = ICFG_DIR,
                     scuba_results_dir: str = SCUBA_RESULTS_DIR,
                     strategy: str = "auto") -> SelectionResult:
    """Select the best ICFG source for a CVE.

    Args:
        cve_id: CVE identifier.
        language: Detected language (c, cpp, javascript, python, etc.).
        gt_files: Ground truth files for coverage comparison (evaluation only).
        gt_functions: Ground truth functions for coverage comparison (evaluation only).
        icfg_base_dir: CodeQL ICFG results directory.
        scuba_results_dir: ScubaTrace results directory.
        strategy: auto, codeql_first, joern_first, scubatrace_first, best_coverage,
                  fuse, or merge.

    Returns:
        SelectionResult with selected path and metadata.
    """
    sources = find_available_sources(cve_id, icfg_base_dir, scuba_results_dir)

    if not sources:
        return SelectionResult(
            selected_path=None, source_type=None,
            selection_reason=f"No ICFG sources available for {cve_id}",
            all_sources=[],
        )

    if gt_files is not None and gt_functions is not None:
        compute_coverage_for_sources(sources, gt_files, gt_functions)

    source_map = {s.source_type: s for s in sources}

    # --- fuse: run pipeline per source, fuse rankings ---
    if strategy == "fuse":
        if len(sources) >= 2:
            source_types = "+".join(s.source_type for s in sources)
            return SelectionResult(
                selected_path=None,
                source_type=SOURCE_FUSED,
                selection_reason=f"Fuse {len(sources)} sources: {source_types}",
                all_sources=_serialize_sources(sources),
            )
        if len(sources) == 1:
            s = sources[0]
            return SelectionResult(s.path, s.source_type,
                                   f"Fuse fallback (single source): {s.source_type} ({s.edge_count} edges)",
                                   _serialize_sources(sources), s.file_coverage, s.func_coverage)
        return SelectionResult(None, None, "Fuse: no sources available", [])

    # --- merge: combine all ICFG CSVs into one ---
    if strategy == "merge":
        if len(sources) >= 2:
            merged_path = _merge_sources(cve_id, sources, scuba_results_dir)
            if merged_path:
                total_edges = sum(s.edge_count for s in sources)
                source_types = "+".join(s.source_type for s in sources)
                return SelectionResult(
                    merged_path, SOURCE_MERGED,
                    f"Merged {len(sources)} sources ({source_types}): {total_edges} total input edges",
                    _serialize_sources(sources), 0.0, 0.0,
                )
        if len(sources) == 1:
            s = sources[0]
            return SelectionResult(s.path, s.source_type,
                                   f"Merge fallback (single): {s.source_type} ({s.edge_count} edges)",
                                   _serialize_sources(sources), s.file_coverage, s.func_coverage)
        return SelectionResult(None, None, "Merge: no sources available", [])

    # --- strategy overrides ---
    if strategy == "codeql_first" and SOURCE_CODEQL in source_map:
        s = source_map[SOURCE_CODEQL]
        return SelectionResult(s.path, s.source_type,
                               f"Strategy 'codeql_first': {s.edge_count} edges",
                               _serialize_sources(sources), s.file_coverage, s.func_coverage)
    if strategy == "joern_first" and SOURCE_JOERN in source_map:
        s = source_map[SOURCE_JOERN]
        return SelectionResult(s.path, s.source_type,
                               f"Strategy 'joern_first': {s.edge_count} edges",
                               _serialize_sources(sources), s.file_coverage, s.func_coverage)
    if strategy == "scubatrace_first" and SOURCE_SCUBATRACE in source_map:
        s = source_map[SOURCE_SCUBATRACE]
        return SelectionResult(s.path, s.source_type,
                               f"Strategy 'scubatrace_first': {s.edge_count} edges",
                               _serialize_sources(sources), s.file_coverage, s.func_coverage)

    # --- best_coverage ---
    if strategy == "best_coverage" and gt_files is not None:
        best = max(sources, key=lambda s: (s.file_coverage, s.func_coverage))
        return SelectionResult(best.path, best.source_type,
                               f"Best coverage: file={best.file_coverage:.3f}, func={best.func_coverage:.3f}",
                               _serialize_sources(sources), best.file_coverage, best.func_coverage)

    # --- auto: heuristic rules ---

    # Language-based preference
    if language == "javascript":
        if SOURCE_CODEQL in source_map:
            s = source_map[SOURCE_CODEQL]
            return SelectionResult(s.path, s.source_type,
                                   f"Auto: JavaScript → CodeQL ({s.edge_count} edges)",
                                   _serialize_sources(sources), s.file_coverage, s.func_coverage)

    # Coverage-based (if GT available)
    if gt_files is not None and len(sources) >= 2:
        best = max(sources, key=lambda s: (s.file_coverage, s.func_coverage))
        return SelectionResult(best.path, best.source_type,
                               f"Auto: best coverage file={best.file_coverage:.3f} ({best.source_type})",
                               _serialize_sources(sources), best.file_coverage, best.func_coverage)

    # Default preference: Joern > CodeQL > ScubaTrace for C/C++; CodeQL > Joern > ScubaTrace for others
    preference_order = (
        [SOURCE_JOERN, SOURCE_CODEQL, SOURCE_SCUBATRACE]
        if language in ("c", "cpp")
        else [SOURCE_CODEQL, SOURCE_JOERN, SOURCE_SCUBATRACE]
    )
    for src_type in preference_order:
        if src_type in source_map:
            s = source_map[src_type]
            return SelectionResult(s.path, s.source_type,
                                   f"Auto: prefer {src_type} for {language} ({s.edge_count} edges)",
                                   _serialize_sources(sources), s.file_coverage, s.func_coverage)

    return SelectionResult(None, None, "No selection made", _serialize_sources(sources))


# ---------------------------------------------------------------------------
# Merge helper
# ---------------------------------------------------------------------------

def _merge_sources(cve_id: str, sources: List[IcfgSource], cache_dir: str) -> Optional[str]:
    """Merge multiple ICFG CSV sources into one (union strategy)."""
    import time

    all_rows: List[tuple] = []
    seen_edges: set = set()
    source_stats = []

    for src in sources:
        rows, edges, skipped = 0, 0, 0
        try:
            with open(src.path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if header is None:
                    source_stats.append({"path": src.path, "type": src.source_type,
                                         "rows": 0, "edges": 0, "skipped": 0})
                    continue
                for row in reader:
                    rows += 1
                    # Normalize to 6 columns
                    while len(row) < 6:
                        row.append("")
                    key = (row[0].strip(), row[1].strip(), row[2].strip(),
                           row[3].strip(), row[4].strip().lower(), row[5].strip())
                    if key not in seen_edges:
                        seen_edges.add(key)
                        all_rows.append(key)
                        edges += 1
                    else:
                        skipped += 1
        except Exception:
            pass
        source_stats.append({"path": src.path, "type": src.source_type,
                             "rows": rows, "edges": edges, "skipped": skipped})

    if not all_rows:
        return None

    os.makedirs(cache_dir, exist_ok=True)
    output_path = os.path.join(cache_dir, f"{cve_id}_merged.csv")

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "function", "srcLine", "dstLine", "edge_type", "target_function"])
        for row in all_rows:
            writer.writerow(row)

    # Write metadata
    meta_path = output_path.replace(".csv", ".meta.json")
    with open(meta_path, "w") as f:
        json.dump({
            "cve_id": cve_id,
            "strategy": "union",
            "sources": [{"type": s.source_type, "path": s.path, "edges": s.edge_count}
                        for s in sources],
            "merged_edges": len(all_rows),
            "source_stats": source_stats,
        }, f, indent=2)

    return output_path


def _serialize_sources(sources: List[IcfgSource]) -> List[dict]:
    return [{"type": s.source_type, "path": s.path, "edges": s.edge_count,
             "files": s.file_count, "functions": s.function_count,
             "file_coverage": s.file_coverage, "func_coverage": s.func_coverage}
            for s in sources]
