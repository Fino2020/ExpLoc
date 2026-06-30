"""
Static analysis evidence extractor for Step1 prompt enrichment.

Queries pre-computed CodeQL alerts and ICFG data-flow snippets,
producing a compact token-efficient table for LLM consumption.
"""

import csv
import os
from typing import Dict, List, Optional, Set

from shared.config import ICFG_DIR, SCUBA_RESULTS_DIR


def _find_codeql_csv(cve_id: str) -> Optional[str]:
    """Locate CodeQL ICFG CSV for a CVE."""
    paths = [
        os.path.join(ICFG_DIR, cve_id, "icfg_icfg_db.csv"),
        os.path.join(ICFG_DIR, cve_id, "icfg_codeql.csv"),
    ]
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def _find_scubatrace_csv(cve_id: str) -> Optional[str]:
    """Locate ScubaTrace ICFG CSV for a CVE."""
    paths = [
        os.path.join(SCUBA_RESULTS_DIR, cve_id, "icfg_scubatrace.csv"),
        os.path.join(SCUBA_RESULTS_DIR, cve_id, "icfg_icfg_db.csv"),
    ]
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def _parse_icfg_csv(csv_path: str, max_rows: int = 5000) -> Dict[str, Set[str]]:
    """Parse ICFG CSV, returning file->{functions} mapping.

    CSV columns vary (4-6). Attempts auto-detection of header format.
    Returns empty dict on failure.
    """
    file_funcs: Dict[str, Set[str]] = {}
    if not csv_path:
        return file_funcs

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = [h.strip().lower().strip('"') for h in next(reader, [])]
            rows = list(reader)
    except Exception:
        return file_funcs

    if len(rows) > max_rows:
        rows = rows[:max_rows]

    # Auto-detect column indices
    col_map = {}
    for idx, name in enumerate(header):
        col_map[name] = idx

    file_col = col_map.get("file", col_map.get("filename", 0))
    func_col = col_map.get("function", col_map.get("func", col_map.get("name", 1)))

    for row in rows:
        if len(row) <= max(file_col, func_col):
            continue
        fpath = row[file_col].strip().strip('"')
        fname = row[func_col].strip().strip('"')
        if fpath:
            file_funcs.setdefault(fpath, set()).add(fname)

    return file_funcs


def _extract_alert_summary(
    csv_path: str,
    candidate_file_set: Set[str],
) -> Dict[str, List[str]]:
    """Extract alert-type summaries per file from CodeQL CSV.

    Returns {file_path: ["alert_type @ L{line}", ...]}.
    """
    alerts: Dict[str, List[str]] = {}
    if not csv_path:
        return alerts

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = [h.strip().lower().strip('"') for h in next(reader, [])]
            rows = list(reader)[:3000]
    except Exception:
        return alerts

    col_map = {name: idx for idx, name in enumerate(header)}

    file_col = col_map.get("file", col_map.get("filename", 0))
    line_col = col_map.get("line", col_map.get("startline", col_map.get("start_line", 1)))
    alert_col = col_map.get("alert", col_map.get("type", col_map.get("vuln_type", col_map.get("kind", 2))))

    for row in rows:
        if len(row) <= max(file_col, alert_col):
            continue
        fpath = row[file_col].strip().strip('"')
        if fpath not in candidate_file_set:
            continue
        line = row[line_col].strip().strip('"') if len(row) > line_col else "?"
        alert_type = row[alert_col].strip().strip('"')
        alerts.setdefault(fpath, []).append(f"{alert_type} @ L{line}")

    return alerts


def load_static_evidence(
    cve_id: str,
    repo_path: str,
    candidate_files: List[str],
    vuln_types: List[str],
) -> str:
    """Assemble static analysis evidence as a compact string for prompt injection.

    Args:
        cve_id: CVE identifier
        repo_path: path to repository (unused, reserved for future expansion)
        candidate_files: files to cross-reference (from commits/issues)
        vuln_types: detected vulnerability type names

    Returns:
        Formatted evidence string, or empty string if no data available.
        Target: under 1500 tokens.
    """
    codeql_path = _find_codeql_csv(cve_id)
    scuba_path = _find_scubatrace_csv(cve_id)

    # If no static analysis data at all, return empty
    if not codeql_path and not scuba_path:
        return ""

    lines = []
    candidate_set = set(candidate_files)

    # 1. CodeQL alert summary
    if codeql_path:
        alerts = _extract_alert_summary(codeql_path, candidate_set)
        if alerts:
            lines.append("CODEQL ALERTS (per candidate file):")
            for fpath, alert_list in sorted(alerts.items()):
                alert_str = ", ".join(alert_list[:3])
                lines.append(f"  {fpath}: {len(alert_list)} alerts ({alert_str})")
            lines.append("")

    # 2. ICFG function coverage — merge ALL available sources for maximum coverage
    all_funcs: Dict[str, Set[str]] = {}
    for csv_path in [codeql_path, scuba_path]:
        if csv_path:
            file_funcs = _parse_icfg_csv(csv_path)
            for fpath, funcs in file_funcs.items():
                all_funcs.setdefault(fpath, set()).update(funcs)

    if all_funcs:
            # Split: files in candidate_set first (prioritized), then others
            matched_files = {f for f in all_funcs if f in candidate_set}
            other_files = {f for f in all_funcs if f not in candidate_set}

            if matched_files or other_files:
                lines.append("ICFG FUNCTION COVERAGE (functions in the static analysis graph):")
                for fpath in sorted(matched_files):
                    func_str = ", ".join(sorted(all_funcs[fpath])[:5])
                    lines.append(f"  [IN CANDIDATES] {fpath}: {func_str}")
                for fpath in sorted(other_files)[:10]:
                    func_str = ", ".join(sorted(all_funcs[fpath])[:5])
                    lines.append(f"  {fpath}: {func_str}")
                lines.append("")

    # 3. ICFG data-flow traces (3-node chains) — use any available source
    best_icfg = codeql_path or scuba_path
    if best_icfg and len(lines) < 30:
        chains = _extract_sink_chains(best_icfg, vuln_types, max_chains=8)
        if chains:
            lines.append("ICFG DATA-FLOW TRACES (entry->mid->sink):")
            for chain in chains:
                lines.append(f"  {chain}")
            lines.append("")

    if not lines:
        return ""

    lines.insert(0, "STATIC ANALYSIS FINDINGS:")
    return "\n".join(lines)


def _match_sink(func_name: str, vuln_types: List[str]) -> bool:
    """Check if function name matches vulnerability sink patterns."""
    from shared.sink_db import get_sinks_for_vuln_types

    sinks = get_sinks_for_vuln_types(vuln_types, "")  # language-agnostic
    if not sinks:
        return False
    name_lower = func_name.lower()
    return any(s.lower() in name_lower for s in sinks)


def _extract_sink_chains(
    csv_path: str,
    vuln_types: List[str],
    max_chains: int = 8,
) -> List[str]:
    """Extract short entry->sink chains from ICFG CSV that match vuln types.

    Returns at most max_chains formatted chain strings.
    """
    import networkx as nx
    try:
        from shared.icfg_loader import load_icfg
        icfg = load_icfg(csv_path)
        G = icfg.graph if icfg else None
    except Exception:
        return []

    if G is None or G.number_of_nodes() == 0:
        return []

    chains = []
    sink_nodes = set()

    # Find sink nodes matching vuln type sink patterns
    for node, attrs in G.nodes(data=True):
        node_name = str(attrs.get("function", node)).lower()
        if _match_sink(node_name, vuln_types):
            sink_nodes.add(node)

    if not sink_nodes:
        # Fallback: use nodes with high out-degree as sinks
        out_degrees = dict(G.out_degree())
        if out_degrees:
            max_out = max(out_degrees.values())
            sink_nodes = {n for n, d in out_degrees.items() if d >= max_out * 0.1}

    # Find entry nodes (high in-degree or no predecessors)
    entry_nodes = {n for n, d in G.in_degree() if d == 0}
    if not entry_nodes:
        in_degrees = dict(G.in_degree())
        if in_degrees:
            min_in = min(in_degrees.values())
            entry_nodes = {n for n, d in in_degrees.items() if d <= min_in + 1}

    # Try to find short paths from entries to sinks
    for sink in list(sink_nodes)[:4]:
        for entry in list(entry_nodes)[:3]:
            try:
                path = nx.shortest_path(G, source=entry, target=sink)
                if len(path) <= 4:
                    names = [str(G.nodes[n].get("function", n)) for n in path]
                    chains.append(" -> ".join(names))
                    if len(chains) >= max_chains:
                        return chains[:max_chains]
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    return chains[:max_chains]
