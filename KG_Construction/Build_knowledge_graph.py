# _*_ coding: utf-8 _*_
#
# Copyright (C) 2026 - 2026 Fino, Inc. All Rights Reserved
#
# @Time    : 2026/4/13 18:53
# @Author  : Fino
# @File    : Build_knowledge_graph.py
# @IDE     : PyCharm
import os
import json
import re
import tempfile
import traceback
from collections import defaultdict
from fnmatch import fnmatch
import multiprocessing as mp
from dotenv import load_dotenv
from git import Repo
# Neo4j removed - using local file-based graphs instead
import networkx as nx

# XML 1.0 invalid control characters (only 0x09, 0x0A, 0x0D are allowed)
_INVALID_XML_BYTES = bytes(set(range(32)) - {9, 10, 13})


def _sanitize_graph_xml(G: nx.DiGraph) -> None:
    """Remove invalid XML bytes from all string attributes in graph nodes/edges.

    Commit messages and issue bodies may contain binary data (memory dumps,
    terminal escape codes, etc.) that are illegal in XML 1.0. This function
    replaces them with spaces in-place.
    """
    for _, data in G.nodes(data=True):
        for k, v in list(data.items()):
            if isinstance(v, str):
                clean = v.encode('utf-8', errors='replace')
                if any(b in clean for b in _INVALID_XML_BYTES):
                    data[k] = clean.decode('utf-8', errors='replace').translate(
                        str.maketrans(
                            ''.join(chr(b) for b in _INVALID_XML_BYTES),
                            ' ' * len(_INVALID_XML_BYTES)
                        )
                    )
    for _, _, data in G.edges(data=True):
        for k, v in list(data.items()):
            if isinstance(v, str):
                clean = v.encode('utf-8', errors='replace')
                if any(b in clean for b in _INVALID_XML_BYTES):
                    data[k] = clean.decode('utf-8', errors='replace').translate(
                        str.maketrans(
                            ''.join(chr(b) for b in _INVALID_XML_BYTES),
                            ' ' * len(_INVALID_XML_BYTES)
                        )
                    )
from datetime import datetime
from issue_timeline_extractor import get_issue_timeline, extract_from_url

load_dotenv()

# ── Configuration ──────────────────────────────────────────────────────
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4j123")
REPOS_BASE_DIR = os.getenv("REPOS_BASE_DIR", r'./repos')
HISTORY_DIR = os.getenv("HISTORY_DIR", r"./history")

# Git empty tree SHA (used for diffing initial commits with no parent)
EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf899d15363ad7e58"

# Batch size for Neo4j UNWIND operations
BATCH_SIZE = 500

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
        repo = Repo(repo_path)
        commit = repo.commit(commit_hash)
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
            if not any(fnmatch(file_path, pat) for pat in SUPPORTED_EXTENSIONS):
                continue

            try:
                raw_diff = diff.diff
                if isinstance(raw_diff, bytes):
                    patch = raw_diff.decode('utf-8', errors='ignore')
                elif raw_diff is None:
                    patch = ''
                else:
                    patch = str(raw_diff)
                new_lines = []
                for line in patch.split('\n'):
                    if line.startswith('+') and not line.startswith('+++'):
                        new_lines.append(line[1:])
                new_content = "\n".join(new_lines)
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
        result = repo.git.log('--all', '--format=%H', f'--grep=#{pr_number}', '-1')
        sha = result.strip()
        return sha if sha else None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════
# Neo4j Knowledge Graph Writer
# ═══════════════════════════════════════════════════════════════════════

class SimpleGraphWriter:
    """将图谱写为本地文件（GraphML），为每个 issue(CVE) 生成独立图谱，并可生成仓库级聚合图谱。"""

    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def clear_graph(self):
        """清理输出目录中已存在的图谱文件（.graphml/.gexf）"""
        removed = 0
        for fn in os.listdir(self.output_dir):
            if fn.endswith('.graphml') or fn.endswith('.gexf') or fn.endswith('.json'):
                try:
                    os.remove(os.path.join(self.output_dir, fn))
                    removed += 1
                except Exception:
                    pass
        print(f"  Cleared {removed} existing graph files in {self.output_dir}.\n")

    def write_batch(self, batch, repo_owner, repo_name):
        """为整个仓库（项目）生成单一的知识图谱并保存为一个文件。"""
        # 索引化便于查找
        commits = { c['commit_uid']: c for c in batch.get('commits', []) }
        files = { f['file_uid']: f for f in batch.get('changed_files', []) }
        funcs = defaultdict(list)
        for fn in batch.get('changed_functions', []):
            funcs[fn['file_uid']].append(fn)
        events = { e['event_uid']: e for e in batch.get('timeline_events', []) }
        resolved = defaultdict(list)
        for rel in batch.get('resolved_by', []):
            resolved[rel['issue_uid']].append(rel)
        event_commits = defaultdict(list)
        for ec in batch.get('event_commits', []):
            event_commits[ec['event_uid']].append(ec['commit_uid'])
        event_refs = defaultdict(list)
        for er in batch.get('event_references', []):
            event_refs[er['event_uid']].append(er)

        # 创建仓库级图（单一图，包含所有 issue/commit/file/function/event）
        G = nx.DiGraph()
        repo_label = f"{repo_owner}_{repo_name}"
        G.graph['repo'] = repo_label

        # 添加 issues (title + body)
        for issue in batch.get('issues', []):
            title_uid = issue['title_uid']
            body_uid = issue['body_uid']
            issue_num = issue.get('issue_number')
            G.add_node(
                title_uid, type='IssueTitle', title=issue.get('title', ''),
                repo_owner=repo_owner, repo_name=repo_name, issue_number=issue_num, url=issue.get('url', '')
            )
            G.add_node(body_uid, type='IssueBody', content=issue.get('content', ''))
            G.add_edge(title_uid, body_uid, type='HAS_BODY')

        # 添加 timeline events 并与 issue 连接
        for ev in batch.get('timeline_events', []):
            ev_uid = ev['event_uid']
            issue_uid = ev['issue_uid']
            G.add_node(
                ev_uid, type='TimelineEvent', timestamp=ev.get('timestamp'), actor=ev.get('actor'),
                event_type=ev.get('event_type'), description=ev.get('description'),
                reference_url=ev.get('reference_url'), reference_detail=ev.get('reference_detail')
            )
            G.add_edge(issue_uid, ev_uid, type='HAS_EVENT')

            # event -> commits
            for c_uid in event_commits.get(ev_uid, []):
                if c_uid in commits:
                    c = commits[c_uid]
                    G.add_node(c_uid, type='Commit', sha=c.get('sha'), message=c.get('message'))
                    G.add_edge(ev_uid, c_uid, type='REFERENCES_COMMIT')

            # event -> cross-references
            for er in event_refs.get(ev_uid, []):
                target_uid = er.get('target_issue_uid')
                G.add_edge(
                    ev_uid,
                    target_uid,
                    type='CROSS_REFERENCES',
                    reference_url=er.get('reference_url'),
                    reference_detail=er.get('reference_detail')
                )

        # 添加 commits 并与 issues 连接（RESOLVED_BY）以及文件/函数
        for rel_list in resolved.values():
            for rel in rel_list:
                issue_uid = rel['issue_uid']
                c_uid = rel['commit_uid']
                pr_number = rel.get('pr_number')
                if c_uid in commits:
                    c = commits[c_uid]
                    G.add_node(c_uid, type='Commit', sha=c.get('sha'), message=c.get('message'))
                    G.add_edge(issue_uid, c_uid, type='RESOLVED_BY', pr_number=pr_number)

        # 将所有文件与函数加入图，并把文件连接到对应 commit
        for f_uid, f in files.items():
            G.add_node(f_uid, type='ChangedFile', path=f.get('path'))
            c_uid = f.get('commit_uid')
            if c_uid:
                G.add_edge(c_uid, f_uid, type='MODIFIED_FILE')
            for fn in funcs.get(f_uid, []):
                func_uid = fn['func_uid']
                G.add_node(func_uid, type='ChangedFunction', name=fn.get('name'), file_path=fn.get('file_path'))
                G.add_edge(f_uid, func_uid, type='CONTAINS_FUNCTION')

        # 保存单一仓库图
        safe_repo_label = repo_label.replace('/', '_').replace('\\', '_')
        out_path = os.path.join(self.output_dir, f"{safe_repo_label}.graphml")
        _sanitize_graph_xml(G)
        try:
            nx.write_graphml(G, out_path)
        except Exception:
            out_path = os.path.join(self.output_dir, f"{safe_repo_label}.gexf")
            nx.write_gexf(G, out_path)

    def get_statistics(self):
        """返回输出目录中图谱文件数量和大小作为简单统计"""
        stats = { }
        total_files = 0
        total_size = 0
        for fn in os.listdir(self.output_dir):
            if fn.endswith('.graphml') or fn.endswith('.gexf'):
                total_files += 1
                total_size += os.path.getsize(os.path.join(self.output_dir, fn))
        stats['graph_files'] = total_files
        stats['total_bytes'] = total_size
        return stats

    @staticmethod
    def _run_in_batches(*_args, **_kwargs):
        # 保留接口兼容性（不再使用）
        pass


# ═══════════════════════════════════════════════════════════════════════
# Repository processing
# ═══════════════════════════════════════════════════════════════════════

def process_repo(history_file_path):
    """处理单个仓库的 issue 历史文件，返回可批量写入 Neo4j 的数据

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

    # 尝试克隆仓库；如果克隆失败，记录警告但继续使用 history JSON 中可用的数据构建图谱
    # （没有本地 repo 时无法解析变更文件/函数，但仍然会生成包含 issues/timeline/commit 引用的图谱）
    repo = None
    try:
        if not os.path.exists(local_repo_path):
            print(f"  Cloning {github_repo_url} ...")
            Repo.clone_from(github_repo_url, local_repo_path)
        repo = Repo(local_repo_path)
    except Exception as e:
        print(f"  Clone failed for {github_repo_url}: {e}")
        print("  Will continue without local repo: commit file/function extraction will be skipped for this repo.")
        repo = None

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
                    # 如果没有本地 repo（克隆失败），仍然创建 Commit 节点（但无法解析变更文件/函数）
                    if repo is not None:
                        commit_obj = repo.commit(raw_sha)
                        full_sha = commit_obj.hexsha
                        message = commit_obj.message.strip()
                        analyzed = True
                    else:
                        # raw_sha 可能已是短 SHA 或完整 SHA，保底使用 raw_sha
                        full_sha = raw_sha
                        message = ''
                        analyzed = False

                    commit_uid = f"{repo_owner}_{repo_name}_commit_{full_sha[:7]}"

                    if commit_uid not in seen_commits:
                        seen_commits.add(commit_uid)
                        batch["commits"].append(
                            {
                                "commit_uid":  commit_uid,
                                "message_uid": f"{commit_uid}_message",
                                "sha":         full_sha,
                                "message":     message,
                                "repo_owner":  repo_owner,
                                "repo_name":   repo_name,
                            }
                        )

                        if analyzed:
                            try:
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
                            except Exception as e:
                                print(f"    [WARN] analyze_commit failed for {full_sha[:7]}: {e}")

                    batch["event_commits"].append(
                        { "event_uid": event_uid, "commit_uid": commit_uid }
                    )
                except Exception as e:
                    print(f"    [WARN] Could not resolve commit {raw_sha} for {repo_owner}/{repo_name}: {e}")
                    # still continue with next commit id
                    continue

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

                # 尝试解析 merge commit 的 message 并决定是否执行文件/函数分析
                analyzed = False
                if repo is not None:
                    try:
                        commit_obj = repo.commit(commit_hash)
                        commit_message = commit_obj.message.strip()
                        analyzed = True
                    except Exception as e:
                        print(
                            f"    [WARN] Could not resolve merge commit {commit_hash} for {repo_owner}/{repo_name}: {e}"
                        )
                        commit_message = ''
                else:
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

                # 仅当本地 repo 可用且解析成功时执行文件/函数分析
                if analyzed:
                    try:
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
                    except Exception as e:
                        print(f"    [WARN] analyze_commit failed for merge commit {commit_hash[:7]}: {e}")

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

# 修改 main 函数如下：
def main():
    os.makedirs(REPOS_BASE_DIR, exist_ok=True)
    graph_output_dir = os.getenv("GRAPH_OUTPUT_DIR", os.path.join(os.path.dirname(HISTORY_DIR), "graphs"))
    print(f"Using local graph output dir: {graph_output_dir}")
    writer = SimpleGraphWriter(graph_output_dir)
    writer.clear_graph()

    json_files = sorted(f for f in os.listdir(HISTORY_DIR) if f.endswith('.json'))
    total = len(json_files)
    print(f"Found {total} repositories to process.\n")

    # 使用多进程池，并行处理
    with mp.Pool(processes=4) as pool:
        results = []
        for idx, filename in enumerate(json_files, 1):
            file_path = os.path.join(HISTORY_DIR, filename)
            repo_label = filename.replace('.json', '')
            print(f"[{idx}/{total}] {repo_label}")
            results.append((file_path, repo_label, idx, total))

        # 并行执行 process_repo
        processed_batches = pool.map(process_repo_wrapper, results)

    # 写入结果
    for batch, (file_path, repo_label, idx, total) in zip(processed_batches, results):
        if batch:
            n_issues = len(batch["issues"])
            n_commits = len(batch["commits"])
            n_events = len(batch.get("timeline_events", []))
            if '_' in repo_label:
                repo_owner, repo_name = repo_label.split('_', 1)
            else:
                repo_owner, repo_name = repo_label, ''
            writer.write_batch(batch, repo_owner, repo_name)
            print(f"    -> {n_issues} issues, {n_commits} commits, {n_events} timeline events written")

    # 打印统计信息
    print("\n" + "=" * 60)
    print("  Knowledge Graph Statistics (file-based)")
    print("=" * 60)
    stats = writer.get_statistics()
    if stats:
        for label, count in stats.items():
            print(f"    {label:25s}: {count}")
    else:
        print("    (empty graph)")
    print("=" * 60)
    print("\nDone.")


# 添加一个包装函数用于多进程调用
def process_repo_wrapper(args):
    file_path, repo_label, idx, total = args
    try:
        return process_repo(file_path)
    except Exception as e:
        print(f"    ERROR in {repo_label}: {e}")
        traceback.print_exc()
        return None


if __name__ == "__main__":
    main()
