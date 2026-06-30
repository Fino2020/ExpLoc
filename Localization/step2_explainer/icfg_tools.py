"""
ICFG Query Tools for Agent — get_callees, get_callers, find_path.

Loads merged CodeQL + ScubaTrace ICFG and provides O(1) edge queries.
Caches loaded ICFGs per CVE with pickle persistence to avoid CSV re-parsing.
"""

import csv
import os
import pickle as pkl
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from shared.config import ICFG_DIR, SCUBA_RESULTS_DIR

# Per-CVE cache: {cve_id: ICFGTools}
_cache: Dict[str, "ICFGTools"] = {}
PICKLE_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "icfg_pickle_cache")
os.makedirs(PICKLE_CACHE_DIR, exist_ok=True)


class ICFGTools:
    """Query interface for merged CodeQL + ScubaTrace ICFG edges."""

    def __init__(self, cve_id: str):
        self.cve_id = cve_id
        self._callees: Dict[Tuple[str, str], Set[Tuple[str, str, str]]] = defaultdict(set)
        self._callers: Dict[Tuple[str, str], Set[Tuple[str, str, str]]] = defaultdict(set)
        self._all_funcs: Set[str] = set()
        self._loaded = False

        # Try pickle cache first
        _pkl_path = os.path.join(PICKLE_CACHE_DIR, f"{cve_id}.pkl")
        if os.path.isfile(_pkl_path):
            try:
                data = pkl.load(open(_pkl_path, 'rb'))
                self._callees = defaultdict(set, {tuple(k): set(tuple(x) for x in v) for k, v in data.get('callees', {})})
                self._callers = defaultdict(set, {tuple(k): set(tuple(x) for x in v) for k, v in data.get('callers', {})})
                self._all_funcs = set(data.get('funcs', []))
                self._loaded = True
                return
            except Exception:
                pass  # fall through to CSV load

        self._load()

        # Save to pickle for future use
        try:
            pkl_data = {
                'callees': {list(k): [list(x) for x in v] for k, v in self._callees.items()},
                'callers': {list(k): [list(x) for x in v] for k, v in self._callers.items()},
                'funcs': list(self._all_funcs),
            }
            pkl.dump(pkl_data, open(_pkl_path, 'wb'))
        except Exception:
            pass

    def _load(self):
        """Load merged ICFG edges into memory."""
        paths = [
            os.path.join(ICFG_DIR, self.cve_id, "icfg_icfg_db.csv"),
            os.path.join(ICFG_DIR, self.cve_id, "icfg_codeql.csv"),
            os.path.join(SCUBA_RESULTS_DIR, self.cve_id, "icfg_scubatrace.csv"),
        ]

        for path in paths:
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.reader(f)
                    header = [h.strip().lower().strip('"') for h in next(reader, [])]
                    rows = list(reader)[:200000]  # cap per file to avoid memory issues
            except Exception:
                continue

            col_map = {name: idx for idx, name in enumerate(header)}
            file_col = col_map.get("file", col_map.get("filename", 0))
            func_col = col_map.get("function", col_map.get("func", col_map.get("name", 1)))
            target_col = col_map.get("target_function", col_map.get("target", 5))
            edge_col = col_map.get("edge_type", 4)

            for row in rows:
                if len(row) <= max(file_col, func_col, target_col):
                    continue
                fpath = row[file_col].strip().strip('"')
                fname = row[func_col].strip().strip('"')
                target = row[target_col].strip().strip('"') if len(row) > target_col else ""
                etype = row[edge_col].strip().strip('"') if len(row) > edge_col else "call"

                if not fname or not target:
                    continue

                key = (fpath, fname)
                self._callees[key].add((fpath, target, etype))
                self._callers[(fpath, target)].add((fpath, fname, etype))
                self._all_funcs.add(fname)
                self._all_funcs.add(target)

        self._loaded = True

    # ── Public query API ──

    def get_callees(self, function: str, file: str = "") -> List[dict]:
        """Get functions called by `function`. Returns [{function, file, edge_type}, ...]."""
        results = []
        seen = set()
        # Try with file, then without
        for key in [(file, function)]:
            for _, target, etype in self._callees.get(key, set()):
                if target not in seen:
                    seen.add(target)
                    results.append({"function": target, "file": "", "edge_type": etype})
        # Also search by function name only
        for (fp, fn), edges in self._callees.items():
            if fn == function:
                for _, target, etype in edges:
                    if target not in seen:
                        seen.add(target)
                        results.append({"function": target, "file": fp, "edge_type": etype})
        return results[:30]

    def get_callers(self, function: str, file: str = "") -> List[dict]:
        """Get functions that call `function`. Returns [{function, file, edge_type}, ...]."""
        results = []
        seen = set()
        for key in [(file, function)]:
            for _, caller, etype in self._callers.get(key, set()):
                if caller not in seen:
                    seen.add(caller)
                    results.append({"function": caller, "file": "", "edge_type": etype})
        for (fp, fn), edges in self._callers.items():
            if fn == function:
                for _, caller, etype in edges:
                    if caller not in seen:
                        seen.add(caller)
                        results.append({"function": caller, "file": fp, "edge_type": etype})
        return results[:30]

    def find_path(self, from_func: str, to_func: str, max_depth: int = 6) -> Optional[List[str]]:
        """BFS from `from_func` to `to_func` through call edges. Returns path or None."""
        if from_func not in self._all_funcs or to_func not in self._all_funcs:
            return None

        from collections import deque
        visited = {from_func}
        queue = deque([(from_func, [from_func])])

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue

            callees = self.get_callees(current)
            for c in callees:
                target = c["function"]
                if target == to_func:
                    return path + [target]
                if target not in visited:
                    visited.add(target)
                    queue.append((target, path + [target]))

        return None

    @property
    def function_count(self) -> int:
        return len(self._all_funcs)


def get_icfg_tools(cve_id: str) -> Optional[ICFGTools]:
    """Get or create cached ICFGTools for a CVE."""
    if cve_id not in _cache:
        tools = ICFGTools(cve_id)
        if tools.function_count == 0:
            return None
        _cache[cve_id] = tools
    return _cache[cve_id]
