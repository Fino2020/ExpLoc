"""Create issue-report-time-filtered knowledge graphs.

For each CVE in ``dataset_with_changed_files_filter.json``, this script:

1. Uses the first issue report as the CVE's issue-report root.
2. Loads the repository-level GraphML knowledge graph.
3. Keeps the root issue and nodes reachable from it.
4. Removes nodes whose publication timestamp is after the issue creation time.
5. Writes one GraphML file named ``{CVE-ID}_IR_KG.graphml``.

The existing KG format does not store timestamps on every node.  Timestamps
are therefore resolved as follows:

* IssueTitle / IssueBody: issue ``created_at`` from the dataset.
* TimelineEvent: the node's ``timestamp`` attribute.
* Commit / CommitMessage: ``committer_date`` (or ``author_date``) from the
  dataset's commit metadata.
* ChangedFile / ChangedFunction: the timestamp of their owning Commit.

Nodes whose timestamps cannot be resolved are retained and reported in the
summary, because deleting them would silently discard graph information.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import networkx as nx


LOGGER = logging.getLogger("filter_data_leakage")


@dataclass(frozen=True)
class IssueRoot:
    """Metadata needed to select and filter one CVE's issue report."""

    cve_id: str
    owner: str
    project: str
    issue_number: str
    created_at: datetime


@dataclass
class FilterStats:
    """Statistics for one filtered graph."""

    cve_id: str
    source_graph: str
    output_graph: str
    root_nodes: int = 0
    selected_nodes: int = 0
    selected_edges: int = 0
    removed_after_cutoff: int = 0
    retained_without_timestamp: int = 0
    warnings: int = 0


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp into a timezone-aware UTC datetime."""

    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_id(value: Any) -> str:
    """Normalize GraphML/data-set identifier values for comparison."""

    if value is None:
        return ""
    text = str(value).strip()
    if text.endswith(".0") and text[:-2].isdigit():
        return text[:-2]
    return text


def load_dataset(path: Path) -> tuple[list[IssueRoot], dict[tuple[str, str, str], datetime], dict[tuple[str, str, str], datetime]]:
    """Load issue roots and timestamp indexes from the vulnerability dataset.

    Returns:
        A tuple containing CVE roots, issue timestamps, and commit timestamps.
    """

    with path.open(encoding="utf-8") as handle:
        records = json.load(handle)

    roots: list[IssueRoot] = []
    issue_times: dict[tuple[str, str, str], datetime] = {}
    commit_times: dict[tuple[str, str, str], datetime] = {}

    for record in records:
        cve_id = str(record.get("cve_id", "")).strip()
        issue_list = record.get("issue_list") or []
        if not cve_id or not issue_list:
            LOGGER.warning("Skipping %s: no issue report", cve_id or "<unknown CVE>")
            continue

        # Index every issue report so cross-referenced issues in the graph can
        # also receive a timestamp.  The project uses the first issue report
        # as the CVE's root report.
        issue = issue_list[0]
        repo = str(issue.get("repo", "")).strip()
        if "/" not in repo:
            LOGGER.warning("Skipping %s: invalid issue repo %r", cve_id, repo)
            continue
        owner, project = repo.split("/", 1)
        issue_number = normalize_id(issue.get("id", issue.get("number")))
        created_at = parse_timestamp(issue.get("created_at"))
        if not issue_number or created_at is None:
            LOGGER.warning("Skipping %s: issue id/time is unavailable", cve_id)
            continue

        root = IssueRoot(cve_id, owner, project, issue_number, created_at)
        roots.append(root)
        for related_issue in issue_list:
            related_number = normalize_id(
                related_issue.get("id", related_issue.get("number"))
            )
            related_time = parse_timestamp(related_issue.get("created_at"))
            if related_number and related_time is not None:
                issue_times[(owner, project, related_number)] = related_time

        for commit in record.get("commit_list") or []:
            sha = normalize_id(commit.get("sha"))
            commit_time = parse_timestamp(commit.get("committer_date"))
            if commit_time is None:
                commit_time = parse_timestamp(commit.get("author_date"))
            if sha and commit_time is not None:
                commit_times[(owner, project, sha)] = commit_time

    return roots, issue_times, commit_times


def graph_candidates(graph_dir: Path, owner: str, project: str) -> list[Path]:
    """Return possible GraphML paths for a repository."""

    label = f"{owner}_{project}"
    candidates = [graph_dir / f"{label}.graphml"]
    if "_" in project:
        candidates.append(graph_dir / f"{owner}_{project.replace('_', '-')}.graphml")
    return list(dict.fromkeys(candidates))


def find_root_nodes(graph: nx.Graph, root: IssueRoot) -> set[str]:
    """Find the title/body nodes belonging to the selected issue report."""

    roots: set[str] = set()
    for node, attrs in graph.nodes(data=True):
        if attrs.get("repo_owner") != root.owner or attrs.get("repo_name") != root.project:
            continue
        if normalize_id(attrs.get("issue_number")) != root.issue_number:
            continue
        if attrs.get("type") in {"IssueTitle", "IssueBody"}:
            roots.add(str(node))
    return roots


def descendants(graph: nx.Graph, roots: set[str]) -> set[str]:
    """Return roots and all nodes reachable through outgoing KG edges."""

    selected = set(roots)
    for root in roots:
        selected.update(nx.descendants(graph, root))
    return selected


def commit_timestamp(
    graph: nx.Graph,
    node: str,
    attrs: dict[str, Any],
    commit_times: dict[tuple[str, str, str], datetime],
) -> datetime | None:
    """Resolve a commit-derived node's timestamp."""

    node_type = attrs.get("type")
    owner = str(attrs.get("repo_owner", ""))
    project = str(attrs.get("repo_name", ""))
    sha = normalize_id(attrs.get("sha"))

    if node_type == "Commit" and sha:
        timestamp = commit_times.get((owner, project, sha))
        if timestamp is not None:
            return timestamp
        # Older KG files do not store commit dates.  A TimelineEvent that
        # references the commit provides the best available publication-time
        # observation in the existing graph format.
        event_times = [
            event_time
            for parent in graph.predecessors(node)
            if graph.nodes[parent].get("type") == "TimelineEvent"
            for event_time in [parse_timestamp(graph.nodes[parent].get("timestamp"))]
            if event_time is not None
        ]
        return min(event_times) if event_times else None

    # CommitMessage, ChangedFile, and ChangedFunction have a Commit ancestor.
    if node_type not in {"CommitMessage", "ChangedFile", "ChangedFunction"}:
        return None
    queue = list(graph.predecessors(node))
    visited: set[str] = set()
    while queue:
        parent = queue.pop()
        if parent in visited:
            continue
        visited.add(parent)
        parent_attrs = graph.nodes[parent]
        if parent_attrs.get("type") == "Commit":
            parent_sha = normalize_id(parent_attrs.get("sha"))
            parent_owner = str(parent_attrs.get("repo_owner", owner))
            parent_project = str(parent_attrs.get("repo_name", project))
            return commit_times.get((parent_owner, parent_project, parent_sha))
        queue.extend(graph.predecessors(parent))
    return None


def resolve_node_timestamp(
    graph: nx.Graph,
    node: str,
    attrs: dict[str, Any],
    issue_times: dict[tuple[str, str, str], datetime],
    commit_times: dict[tuple[str, str, str], datetime],
) -> datetime | None:
    """Resolve a node's publication timestamp according to its node type."""

    node_type = attrs.get("type")
    if node_type == "TimelineEvent":
        return parse_timestamp(attrs.get("timestamp"))
    if node_type in {"IssueTitle", "IssueBody"}:
        key = (
            str(attrs.get("repo_owner", "")),
            str(attrs.get("repo_name", "")),
            normalize_id(attrs.get("issue_number")),
        )
        return issue_times.get(key)
    if node_type == "Commit":
        return commit_timestamp(graph, node, attrs, commit_times)
    if node_type in {"CommitMessage", "ChangedFile", "ChangedFunction"}:
        return commit_timestamp(graph, node, attrs, commit_times)
    return None


def filter_graph(
    graph: nx.Graph,
    root: IssueRoot,
    issue_times: dict[tuple[str, str, str], datetime],
    commit_times: dict[tuple[str, str, str], datetime],
) -> tuple[nx.Graph, FilterStats]:
    """Select one issue subgraph and remove nodes published after the cutoff."""

    root_nodes = find_root_nodes(graph, root)
    stats = FilterStats(root.cve_id, "", "", root_nodes=len(root_nodes))
    if not root_nodes:
        raise ValueError(
            f"Cannot find issue #{root.issue_number} in graph "
            f"for {root.owner}/{root.project}"
        )

    selected_nodes = descendants(graph, root_nodes)
    filtered = graph.subgraph(selected_nodes).copy()
    stats.selected_nodes = filtered.number_of_nodes()
    stats.selected_edges = filtered.number_of_edges()

    to_remove: list[str] = []
    unknown_types: Counter[str] = Counter()
    for node, attrs in filtered.nodes(data=True):
        timestamp = resolve_node_timestamp(
            filtered, str(node), attrs, issue_times, commit_times
        )
        if timestamp is None:
            stats.retained_without_timestamp += 1
            unknown_types[str(attrs.get("type", "Unknown"))] += 1
            continue
        if timestamp > root.created_at:
            to_remove.append(node)

    filtered.remove_nodes_from(to_remove)
    stats.removed_after_cutoff = len(to_remove)
    if unknown_types:
        LOGGER.warning(
            "%s retained %d nodes without timestamps: %s",
            root.cve_id,
            stats.retained_without_timestamp,
            dict(unknown_types),
        )
        stats.warnings += 1
    return filtered, stats


def process_all(
    dataset_path: Path,
    graph_dir: Path,
    output_dir: Path,
) -> list[FilterStats]:
    """Process all CVEs in the input dataset."""

    roots, issue_times, commit_times = load_dataset(dataset_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    stats: list[FilterStats] = []

    graph_cache: dict[Path, nx.Graph] = {}
    invalid_graphs: set[Path] = set()
    for root in roots:
        candidates = graph_candidates(graph_dir, root.owner, root.project)
        graph_path = next((path for path in candidates if path.exists()), None)
        if graph_path is None:
            LOGGER.warning(
                "%s: GraphML not found; checked %s",
                root.cve_id,
                ", ".join(str(path) for path in candidates),
            )
            continue
        if graph_path in invalid_graphs:
            continue

        if graph_path not in graph_cache:
            try:
                graph_cache[graph_path] = nx.read_graphml(graph_path)
            except Exception as error:
                invalid_graphs.add(graph_path)
                LOGGER.warning(
                    "%s: cannot read GraphML %s; skipping repository: %s",
                    root.cve_id,
                    graph_path,
                    error,
                )
                continue
        graph = graph_cache[graph_path]
        try:
            filtered, item_stats = filter_graph(
                graph, root, issue_times, commit_times
            )
        except ValueError as error:
            LOGGER.warning("%s: %s", root.cve_id, error)
            continue

        output_path = output_dir / f"{root.cve_id}_IR_KG.graphml"
        nx.write_graphml(filtered, output_path)
        item_stats.source_graph = str(graph_path)
        item_stats.output_graph = str(output_path)
        stats.append(item_stats)
        LOGGER.info(
            "%s: %d -> %d nodes, removed %d after %s",
            root.cve_id,
            item_stats.selected_nodes,
            filtered.number_of_nodes(),
            item_stats.removed_after_cutoff,
            root.created_at.isoformat(),
        )

    return stats


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "Dataset"
        / "dataset_with_changed_files_filter.json",
    )
    parser.add_argument(
        "--graph-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "Graphs",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "IR_KG_Data_Leakage",
    )
    parser.add_argument("--cve", help="Process only one CVE for testing")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> None:
    """Run the data-leakage KG filtering command."""

    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(levelname)s: %(message)s",
    )

    if args.cve:
        # Keep the script's public input as the full dataset while allowing a
        # cheap one-CVE validation run.
        with args.dataset.open(encoding="utf-8") as handle:
            records = json.load(handle)
        records = [record for record in records if record.get("cve_id") == args.cve]
        if not records:
            parser.error(f"CVE not found in dataset: {args.cve}")
        temporary_dataset = args.output_dir / ".single_cve_dataset.json"
        args.output_dir.mkdir(parents=True, exist_ok=True)
        temporary_dataset.write_text(
            json.dumps(records, ensure_ascii=False), encoding="utf-8"
        )
        try:
            results = process_all(temporary_dataset, args.graph_dir, args.output_dir)
        finally:
            temporary_dataset.unlink(missing_ok=True)
    else:
        results = process_all(args.dataset, args.graph_dir, args.output_dir)

    print(f"Processed CVEs: {len(results)}")
    print(f"Output directory: {args.output_dir}")
    print(f"Output files: {len(list(args.output_dir.glob('*_IR_KG.graphml')))}")


if __name__ == "__main__":
    main()
