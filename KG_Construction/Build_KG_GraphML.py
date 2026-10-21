# _*_ coding: utf-8 _*_
#
# Copyright (C) 2026 - 2026 Fino, Inc. All Rights Reserved
#
# @Time    : 2026/4/13 18:53
# @Author  : Fino
# @File    : Build_KG_GraphML.py
# @IDE     : PyCharm
import os
import json
import re
import tempfile
import traceback
from collections import defaultdict

from dotenv import load_dotenv
from git import Repo
import networkx as nx

# XML 1.0 invalid control characters (only 0x09, 0x0A, 0x0D are allowed)
_INVALID_XML_BYTES = bytes(set(range(32)) - {9, 10, 13})


def _sanitize_graph_xml(G: nx.DiGraph) -> None:
    """Remove invalid XML bytes from all string attributes in graph nodes/edges."""
    _trans = str.maketrans(
        ''.join(chr(b) for b in _INVALID_XML_BYTES),
        ' ' * len(_INVALID_XML_BYTES)
    )
    for _, data in G.nodes(data=True):
        for k, v in list(data.items()):
            if isinstance(v, str):
                clean = v.encode('utf-8', errors='replace')
                if any(b in clean for b in _INVALID_XML_BYTES):
                    data[k] = clean.decode('utf-8', errors='replace').translate(_trans)
    for _, _, data in G.edges(data=True):
        for k, v in list(data.items()):
            if isinstance(v, str):
                clean = v.encode('utf-8', errors='replace')
                if any(b in clean for b in _INVALID_XML_BYTES):
                    data[k] = clean.decode('utf-8', errors='replace').translate(_trans)

from datetime import datetime
from issue_timeline_extractor import get_issue_timeline, extract_from_url
from tqdm import tqdm

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────
REPOS_BASE_DIR = os.getenv("REPOS_BASE_DIR", r'/mnt/d/Desktop/Localization_Repo')
HISTORY_DIR = os.getenv("HISTORY_DIR", r"/mnt/d/Desktop/VulnLocalization/KG_Construction/history")
OUTPUT_GRAPHML_DIR = os.getenv("OUTPUT_GRAPHML_DIR", r"/mnt/d/Desktop/VulnLocalization/KG_Construction/Graphs")

# Git empty tree SHA (used for diffing initial commits with no parent)
EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf899d15363ad7e58"

# 支持提取函数的代码文件扩展名
SUPPORTED_EXTENSIONS = [
    '*.js', '*.jsx', '*.ts', '*.tsx',
    '*.py', '*.pyw',
    '*.c', '*.h', '*.cpp', '*.cc', '*.cxx',
    '*.hpp', '*.hh', '*.hxx',
    '*.java',
    '*.go',
    '*.rs',
    '*.swift',
    '*.kt', '*.kts',
    '*.cs',
    '*.rb',
    '*.php',
    '*.scala',
    '*.sh', '*.bash',
]
SUPPORTED_SUFFIXES = tuple(ext[1:] for ext in SUPPORTED_EXTENSIONS)

REPO_CACHE = { }
COMMIT_CACHE = { }
MERGE_COMMIT_CACHE = { }


# ═══════════════════════════════════════════════════════════════════════
# Function extraction (regex-based, per language)
# ═══════════════════════════════════════════════════════════════════════

def extract_functions(source_code, file_path):
    """使用正则表达式提取各语言函数/方法名"""
    file_ext = os.path.splitext(file_path)[1].lower()

    # JavaScript / TypeScript
    if file_ext in ('.js', '.jsx', '.ts', '.tsx'):
        pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:\([^)]*\))\s*=>|class\s+(\w+))'
        for match in re.finditer(pattern, source_code):
            yield match.group(1) or match.group(2) or match.group(3)

    # Python
    elif file_ext in ('.py', '.pyw'):
        pattern = r'\b(def|class)\s+(\w+)\s*\('
        for match in re.finditer(pattern, source_code):
            yield match.group(2)

    # C / C++
    elif file_ext in ('.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx'):
        pattern = (r'(?:^|[\n\r])[ \t]*'
                   r'(?:(?:static|extern|inline|virtual|explicit|constexpr|override)\s+)*'
                   r'[\w:*&<>\[\]]+(?:\s+[\w:*&<>\[\]]+)*\s+(\w+)\s*\([^;]*\)\s*'
                   r'(?:const\s*)?(?:noexcept\s*)?\{')
        for match in re.finditer(pattern, source_code, re.MULTILINE):
            name = match.group(1)
            if name not in { 'if', 'for', 'while', 'switch', 'catch' }:
                yield name

    # Java
    elif file_ext == '.java':
        for match in re.finditer(r'\b(?:class|interface|enum)\s+(\w+)', source_code):
            yield match.group(1)
        pattern = (r'\b(?:public|private|protected|static|final|abstract|synchronized|native|default)\b'
                   r'[^;{(]*\s(\w+)\s*\([^;]*\)\s*(?:throws\s+[\w,\s]+)?\{')
        for match in re.finditer(pattern, source_code):
            name = match.group(1)
            if name not in { 'if', 'for', 'while', 'switch', 'catch', 'try', 'new' }:
                yield name

    # Go
    elif file_ext == '.go':
        pattern = r'\bfunc\s+(?:\(\s*\w*\s*\*?[\w.]+\s*\)\s+)?(\w+)\s*\('
        for match in re.finditer(pattern, source_code):
            yield match.group(1)

    # Rust
    elif file_ext == '.rs':
        pattern = r'\b(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*[(<]'
        for match in re.finditer(pattern, source_code):
            yield match.group(1)

    # Swift
    elif file_ext == '.swift':
        for match in re.finditer(r'\b(?:class|struct|enum|protocol)\s+(\w+)', source_code):
            yield match.group(1)
        pattern = (r'\b(?:(?:public|private|internal|fileprivate|open)\s+)?'
                   r'(?:(?:static|class|override)\s+)?func\s+(\w+)\s*\(')
        for match in re.finditer(pattern, source_code):
            yield match.group(1)

    # Kotlin
    elif file_ext in ('.kt', '.kts'):
        for match in re.finditer(r'\b(?:class|object|interface)\s+(\w+)', source_code):
            yield match.group(1)
        pattern = (r'\b(?:(?:public|private|internal|protected)\s+)?'
                   r'(?:(?:override|inline|suspend)\s+)*fun\s+(\w+)\s*[(<]')
        for match in re.finditer(pattern, source_code):
            yield match.group(1)

    # C#
    elif file_ext == '.cs':
        for match in re.finditer(r'\b(?:class|interface|struct|enum)\s+(\w+)', source_code):
            yield match.group(1)
        pattern = (r'\b(?:public|private|protected|internal|static|virtual|override|abstract|async)\b'
                   r'[^;{(]*\s(\w+)\s*\([^;]*\)\s*(?:where\s+[^{]*)?\{')
        for match in re.finditer(pattern, source_code):
            name = match.group(1)
            if name not in { 'if', 'for', 'while', 'switch', 'catch', 'foreach', 'using' }:
                yield name

    # Ruby
    elif file_ext == '.rb':
        for match in re.finditer(r'\b(?:def|class|module)\s+(\w+)', source_code):
            yield match.group(1)

    # PHP
    elif file_ext == '.php':
        for match in re.finditer(r'\b(?:class|interface|trait)\s+(\w+)', source_code):
            yield match.group(1)
        pattern = r'\b(?:public\s+|private\s+|protected\s+)?(?:static\s+)?function\s+(\w+)\s*\('
        for match in re.finditer(pattern, source_code):
            yield match.group(1)

    # Scala
    elif file_ext == '.scala':
        for match in re.finditer(r'\b(?:def|class|object|trait)\s+(\w+)', source_code):
            yield match.group(1)

    # Shell
    elif file_ext in ('.sh', '.bash'):
        pattern = r'(?:function\s+(\w+)\s*\{|(\w+)\s*\(\s*\)\s*\{)'
        for match in re.finditer(pattern, source_code):
            yield match.group(1) or match.group(2)


def is_supported_source(file_path):
    lower = file_path.lower()
    return lower.endswith(SUPPORTED_SUFFIXES)


def get_commit(repo, repo_path, commit_hash):
    cache_key = (repo_path, commit_hash)
    commit = COMMIT_CACHE.get(cache_key)
    if commit is None:
        commit = repo.commit(commit_hash)
        COMMIT_CACHE[cache_key] = commit
    return commit


# ═══════════════════════════════════════════════════════════════════════
# Git analysis
# ═══════════════════════════════════════════════════════════════════════

def analyze_commit(repo_path, commit_hash):
    """分析 commit 中的变更文件和函数

    Returns:
        (changed_files, changed_functions)
        changed_files: list[str] — 所有变更文件路径
        changed_functions: dict[str, set[str]] — 仅代码文件中提取到的函数名
    """
    try:
        repo = REPO_CACHE.get(repo_path)
        if repo is None:
            repo = Repo(repo_path)
            REPO_CACHE[repo_path] = repo

        commit = get_commit(repo, repo_path, commit_hash)

        parent = commit.parents[0] if commit.parents else None

        changed_files = []
        changed_functions = defaultdict(set)

        # [BugFix #1] 正确的 diff 方向: parent → commit，+ 行 = commit 中新增的代码
        # [BugFix #3] 初始 commit 无 parent 时，使用 empty tree 作为基准
        if parent:
            diffs = parent.diff(commit, create_patch=True)
        else:
            empty_tree = repo.tree(EMPTY_TREE_SHA)
            diffs = empty_tree.diff(commit.tree, create_patch=True)

        for diff in diffs:
            file_path = diff.b_path if diff.b_path else diff.a_path
            if not file_path:
                continue

            # [BugFix #2] 所有变更文件都记录，不仅限于代码文件
            changed_files.append(file_path)

            # 只对支持的代码文件进行函数提取
            if not is_supported_source(file_path):
                continue

            try:
                if diff.b_blob is not None:
                    new_content = diff.b_blob.data_stream.read().decode('utf-8', errors='ignore')
                else:
                    new_content = ''
                for func in extract_functions(new_content, file_path):
                    changed_functions[file_path].add(func)
            except Exception as e:
                print(f"    Error parsing diff of {file_path}: {e}")

        return changed_files, dict(changed_functions)

    except Exception as e:
        print(f"    Error analyzing commit {commit_hash[:10]}: {e}")
        return [], { }


def find_merge_commit(repo, pr_number):
    """
    通过PR编号在git历史中查找对应的合并commit SHA。
    利用 git log --grep 匹配 commit message 中的 '#<pr_number>' 字样。
    """
    try:
        cache_key = (repo.working_tree_dir, pr_number)
        if cache_key in MERGE_COMMIT_CACHE:
            return MERGE_COMMIT_CACHE[cache_key]
        result = repo.git.log('--all', '--format=%H', f'--grep=#{pr_number}', '-1')
        sha = result.strip()
        MERGE_COMMIT_CACHE[cache_key] = sha if sha else None
        return MERGE_COMMIT_CACHE[cache_key]
    except Exception:
        return None


class KnowledgeGraphWriter:
    """封装 NetworkX 图谱写入操作，使用.graphml格式保存"""

    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def create_graph(self):
        """创建一个新的空图"""
        return nx.MultiDiGraph()

    def add_nodes_and_edges(self, graph, batch):
        """向图中添加节点和边"""
        # 添加 IssueTitle 节点
        for issue in batch["issues"]:
            graph.add_node(
                issue["title_uid"],
                type="IssueTitle",
                title=issue["title"],
                repo_owner=issue["repo_owner"],
                repo_name=issue["repo_name"],
                issue_number=issue["issue_number"],
                url=issue["url"]
            )

            # 添加对应的 IssueBody 节点和 HAS_BODY 边
            graph.add_node(
                issue["body_uid"],
                type="IssueBody",
                content=issue["content"],
                repo_owner=issue["repo_owner"],
                repo_name=issue["repo_name"],
                issue_number=issue["issue_number"]
            )
            graph.add_edge(issue["title_uid"], issue["body_uid"], relation="HAS_BODY")

        # 添加 Commit 节点
        for commit in batch["commits"]:
            graph.add_node(
                commit["commit_uid"],
                type="Commit",
                sha=commit["sha"],
                repo_owner=commit["repo_owner"],
                repo_name=commit["repo_name"]
            )

            # 添加对应的 CommitMessage 节点和 HAS_MESSAGE 边
            graph.add_node(
                commit["message_uid"],
                type="CommitMessage",
                content=commit["message"]
            )
            graph.add_edge(commit["commit_uid"], commit["message_uid"], relation="HAS_MESSAGE")

        # 添加 RESOLVED_BY 关系
        for rel in batch["resolved_by"]:
            if graph.has_node(rel["issue_uid"]) and graph.has_node(rel["commit_uid"]):
                graph.add_edge(
                    rel["issue_uid"], rel["commit_uid"],
                    relation="RESOLVED_BY", pr_number=rel["pr_number"]
                )

        # 添加 MODIFIED_FILE 关系
        for file_data in batch["changed_files"]:
            graph.add_node(
                file_data["file_uid"],
                type="ChangedFile",
                path=file_data["path"]
            )
            if graph.has_node(file_data["commit_uid"]):
                graph.add_edge(
                    file_data["commit_uid"], file_data["file_uid"],
                    relation="MODIFIED_FILE"
                )

        # 添加 CONTAINS_FUNCTION 关系
        for func_data in batch["changed_functions"]:
            graph.add_node(
                func_data["func_uid"],
                type="ChangedFunction",
                name=func_data["name"],
                file_path=func_data["file_path"]
            )
            if graph.has_node(func_data["file_uid"]):
                graph.add_edge(
                    func_data["file_uid"], func_data["func_uid"],
                    relation="CONTAINS_FUNCTION"
                )

        # 添加 TimelineEvent 节点和 HAS_EVENT 关系
        for event in batch.get("timeline_events", []):
            graph.add_node(
                event["event_uid"],
                type="TimelineEvent",
                timestamp=event["timestamp"],
                actor=event["actor"],
                event_type=event["event_type"],
                description=event["description"],
                reference_url=event["reference_url"],
                reference_detail=event["reference_detail"]
            )
            if graph.has_node(event["issue_uid"]):
                graph.add_edge(event["issue_uid"], event["event_uid"], relation="HAS_EVENT")

        # 添加 CROSS_REFERENCES 关系
        for ref in batch.get("event_references", []):
            if (graph.has_node(ref["event_uid"]) and
                    graph.has_node(ref["target_issue_uid"])):
                graph.add_edge(
                    ref["event_uid"], ref["target_issue_uid"],
                    relation="CROSS_REFERENCES",
                    reference_url=ref["reference_url"],
                    reference_detail=ref["reference_detail"]
                )

        # 添加 REFERENCES_COMMIT 关系
        for ecommit in batch.get("event_commits", []):
            if (graph.has_node(ecommit["event_uid"]) and
                    graph.has_node(ecommit["commit_uid"])):
                graph.add_edge(
                    ecommit["event_uid"], ecommit["commit_uid"],
                    relation="REFERENCES_COMMIT"
                )

    def save_graph_to_graphml(self, graph, filename):
        """将图保存为.graphml文件"""
        filepath = os.path.join(self.output_dir, filename)
        _sanitize_graph_xml(graph)
        nx.write_graphml(graph, filepath)
        print(f"    Saved graph to {filepath}")

    def get_statistics(self, graph):
        """获取图的统计信息"""
        stats = { }
        stats["nodes"] = graph.number_of_nodes()
        stats["edges"] = graph.number_of_edges()

        node_types = defaultdict(int)
        edge_types = defaultdict(int)

        for node_id, data in graph.nodes(data=True):
            node_type = data.get("type", "Unknown")
            node_types[node_type] += 1

        for u, v, key, data in graph.edges(keys=True, data=True):
            edge_type = data.get("relation", "Unknown")
            edge_types[edge_type] += 1

        stats["node_types"] = dict(node_types)
        stats["edge_types"] = dict(edge_types)

        return stats


# ═══════════════════════════════════════════════════════════════════════
# Repository processing
# ═══════════════════════════════════════════════════════════════════════

def process_repo(history_file_path):
    """处理单个仓库的 issue 历史文件，返回图谱数据

    Returns:
        dict with keys: issues, commits, resolved_by, changed_files, changed_functions
        如果仓库克隆失败或无数据，返回 None
    """

    filename = os.path.basename(history_file_path).replace('.json', '')
    if '_' not in filename:
        return None

    repo_owner, repo_name = filename.split('_', 1)
    github_repo_url = f"https://github.com/{repo_owner}/{repo_name}"
    local_repo_path = os.path.join(REPOS_BASE_DIR, filename)

    # 克隆仓库
    try:
        if not os.path.exists(local_repo_path):
            print(f"  Cloning {github_repo_url} ...")
            Repo.clone_from(github_repo_url, local_repo_path)
        repo = Repo(local_repo_path)
    except Exception as e:
        print(f"  Clone failed for {github_repo_url}: {e}")
        return None

    with open(history_file_path, 'r', encoding='utf-8') as f:
        issues = json.load(f)

    # 批量数据收集
    batch = {
        "issues":            [],
        "commits":           [],
        "resolved_by":       [],
        "changed_files":     [],
        "changed_functions": [],
        "timeline_events":   [],
        "event_references":  [],
        "event_commits":     [],
    }
    seen_commits = set()

    for issue in issues:
        issue_num = issue['number']
        prefix = f"{repo_owner}_{repo_name}_issue_{issue_num}"

        # ── Issue Title + Body ────────────────────────────────────────
        batch["issues"].append(
            {
                "title_uid":    f"{prefix}_title",
                "body_uid":     f"{prefix}_body",
                "title":        issue.get('title', ''),
                "content":      issue.get('body') or '',
                "repo_owner":   repo_owner,
                "repo_name":    repo_name,
                "issue_number": issue_num,
                "url":          issue.get('url', ''),
            }
        )

        # ── Issue Timeline Events ─────────────────────────────────────
        try:
            timeline = get_issue_timeline(repo_owner, repo_name, issue_num)
        except Exception as e:
            print(f"    [WARN] Timeline fetch failed for issue #{issue_num}: {e}")
            timeline = []

        for idx, event in enumerate(timeline):
            event_uid = f"{prefix}_event_{idx}"
            batch["timeline_events"].append(
                {
                    "event_uid":        event_uid,
                    "issue_uid":        f"{prefix}_title",
                    "timestamp":        event["timestamp"],
                    "actor":            event["actor"],
                    "event_type":       event["event_type"],
                    "description":      event["description"],
                    "reference_url":    event["references"][0] if event["references"] else "",
                    "reference_detail": event["reference_details"],
                }
            )

            # cross-referenced 事件：尝试链接到目标 issue 节点
            if event["event_type"] == "cross-referenced" and event["references"]:
                for ref_url in event["references"]:
                    try:
                        ref_owner, ref_repo, ref_num = extract_from_url(ref_url)
                        target_uid = f"{ref_owner}_{ref_repo}_issue_{ref_num}_title"
                        batch["event_references"].append(
                            {
                                "event_uid":        event_uid,
                                "target_issue_uid": target_uid,
                                "reference_url":    ref_url,
                                "reference_detail": event["reference_details"],
                            }
                        )
                    except Exception:
                        pass

            # timeline 事件中引用的 commit：创建 Commit 节点并链接
            for raw_sha in event.get("commit_ids", []):
                try:
                    commit_obj = get_commit(repo, local_repo_path, raw_sha)
                    full_sha = commit_obj.hexsha
                    commit_uid = f"{repo_owner}_{repo_name}_commit_{full_sha[:7]}"

                    if commit_uid not in seen_commits:
                        seen_commits.add(commit_uid)
                        batch["commits"].append(
                            {
                                "commit_uid":  commit_uid,
                                "message_uid": f"{commit_uid}_message",
                                "sha":         full_sha,
                                "message":     commit_obj.message.strip(),
                                "repo_owner":  repo_owner,
                                "repo_name":   repo_name,
                            }
                        )
                        changed_files, changed_functions = analyze_commit(
                            local_repo_path, full_sha
                        )
                        for fp in changed_files:
                            path_key = fp.replace('/', '_').replace('\\', '_')
                            file_uid = f"{commit_uid}_file_{path_key}"
                            batch["changed_files"].append(
                                { "file_uid": file_uid, "commit_uid": commit_uid, "path": fp }
                            )
                            for fn in changed_functions.get(fp, []):
                                batch["changed_functions"].append(
                                    {
                                        "func_uid":  f"{file_uid}_func_{fn}",
                                        "file_uid":  file_uid,
                                        "name":      fn,
                                        "file_path": fp,
                                    }
                                )

                    batch["event_commits"].append(
                        { "event_uid": event_uid, "commit_uid": commit_uid }
                    )
                except Exception:
                    pass

        # ── 判断是否被 PR 关闭并有 commit ─────────────────────────────
        if not issue.get('closed', False):
            continue

        pr_refs = issue.get('closedByPullRequestsReferences') or []
        if not pr_refs:
            continue

        for pr_ref in pr_refs:
            pr_number = pr_ref.get('number')
            if not pr_number:
                continue

            commit_hash = find_merge_commit(repo, pr_number)
            if not commit_hash:
                print(f"    [WARN] No merge commit for PR #{pr_number}")
                continue

            commit_uid = f"{repo_owner}_{repo_name}_commit_{commit_hash[:7]}"

            # 避免重复分析同一 commit
            if commit_uid not in seen_commits:
                seen_commits.add(commit_uid)

                try:
                    commit_message = get_commit(repo, local_repo_path, commit_hash).message.strip()
                except Exception:
                    commit_message = ''

                batch["commits"].append(
                    {
                        "commit_uid":  commit_uid,
                        "message_uid": f"{commit_uid}_message",
                        "sha":         commit_hash,
                        "message":     commit_message,
                        "repo_owner":  repo_owner,
                        "repo_name":   repo_name,
                    }
                )

                # 分析变更文件和函数
                changed_files, changed_functions = analyze_commit(local_repo_path, commit_hash)

                for file_path in changed_files:
                    path_key = file_path.replace('/', '_').replace('\\', '_')
                    file_uid = f"{commit_uid}_file_{path_key}"

                    batch["changed_files"].append(
                        {
                            "file_uid":   file_uid,
                            "commit_uid": commit_uid,
                            "path":       file_path,
                        }
                    )

                    for func_name in changed_functions.get(file_path, []):
                        batch["changed_functions"].append(
                            {
                                "func_uid":  f"{file_uid}_func_{func_name}",
                                "file_uid":  file_uid,
                                "name":      func_name,
                                "file_path": file_path,
                            }
                        )

            # Issue → Commit 关系
            batch["resolved_by"].append(
                {
                    "issue_uid":  f"{prefix}_title",
                    "commit_uid": commit_uid,
                    "pr_number":  pr_number,
                }
            )
    return batch


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════

def main():
    os.makedirs(REPOS_BASE_DIR, exist_ok=True)
    os.makedirs(OUTPUT_GRAPHML_DIR, exist_ok=True)

    print(f"Initializing Knowledge Graph Writer...")
    writer = KnowledgeGraphWriter(OUTPUT_GRAPHML_DIR)

    json_files = sorted(f for f in os.listdir(HISTORY_DIR) if f.endswith('.json'))
    total = len(json_files)
    print(f"Found {total} repositories to process.\n")

    for idx, filename in enumerate(tqdm(json_files, desc="Processing Repositories", unit="repo"), 1):
        file_path = os.path.join(HISTORY_DIR, filename)
        repo_label = filename.replace('.json', '')
        print(f"[{idx}/{total}] {repo_label}")
        if os.path.exists(os.path.join(OUTPUT_GRAPHML_DIR, repo_label + ".graphml")):
            print(f"    [SKIP] {repo_label} already exists")
            continue
        try:
            batch = process_repo(file_path)
            if batch:
                # 创建新的图
                G = writer.create_graph()

                # 添加节点和边
                writer.add_nodes_and_edges(G, batch)

                # 生成.graphml文件名
                graphml_filename = f"{repo_label}.graphml"

                # 保存图
                writer.save_graph_to_graphml(G, graphml_filename)

                # 显示统计信息
                stats = writer.get_statistics(G)
                n_issues = len(batch["issues"])
                n_commits = len(batch["commits"])
                n_events = len(batch.get("timeline_events", []))

                print(f"    -> {n_issues} issues, {n_commits} commits, {n_events} timeline events processed")
                print(f"    -> Graph: {stats['nodes']} nodes, {stats['edges']} edges")

        except Exception as e:
            print(f"    ERROR: {e}")
            traceback.print_exc()

    print("\nDone.")


if __name__ == "__main__":
    main()
