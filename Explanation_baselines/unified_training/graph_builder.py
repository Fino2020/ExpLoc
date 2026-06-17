"""Tree-sitter call graph → PyG Data (replaces Joern for simplicity)."""
import os, sys, re
import torch
import numpy as np
from torch_geometric.data import Data
from collections import defaultdict

# Add our Localization project for tree-sitter utils
_LOC_PATH = "/mnt/d/Desktop/VulnLocalization/Localization"
if _LOC_PATH not in sys.path:
    sys.path.insert(0, _LOC_PATH)

def _get_parser(lang_key):
    """Get tree-sitter parser (lazy init)."""
    try:
        from tree_sitter import Language, Parser
    except ImportError:
        from tree_sitter import Language, Parser
    if not hasattr(_get_parser, "_parsers"):
        _get_parser._parsers = {}
    if lang_key not in _get_parser._parsers:
        try:
            so_paths = {
                "c": "/home/fino/anaconda3/envs/VulnLocalization/lib/python3.12/site-packages/tree_sitter_language_pack/languages.so",
                "python": "/home/fino/anaconda3/envs/VulnLocalization/lib/python3.12/site-packages/tree_sitter_language_pack/languages.so",
                "java": "/home/fino/anaconda3/envs/VulnLocalization/lib/python3.12/site-packages/tree_sitter_language_pack/languages.so",
            }
            # Try shared lib
            import glob as _g
            so_files = list(_g.glob("/home/fino/anaconda3/envs/VulnLocalization/**/tree_sitter_language_pack/languages.so", recursive=True))
            if so_files:
                lang_lib = Language(so_files[0], lang_key)
            else:
                return None
            parser = Parser()
            parser.set_language(lang_lib)
            _get_parser._parsers[lang_key] = parser
        except Exception:
            return None
    return _get_parser._parsers[lang_key]

def _detect_lang(code):
    """Detect language from code content."""
    code_lower = code.lower() if code else ""
    java_indicators = ["public class", "import java", "@override", "system.out", "void main(string"]
    py_indicators = ["def ", "import ", "from ", "self.", "__init__", "print(", "class ", ":"]
    c_indicators = ["#include", "int main", "void ", "printf(", "char ", "->", "size_t"]
    java_score = sum(1 for kw in java_indicators if kw in code_lower)
    py_score = sum(1 for kw in py_indicators if kw in code_lower[:500])
    c_score = sum(1 for kw in c_indicators if kw in code_lower[:500])
    return "java" if java_score > max(py_score, c_score) else ("python" if py_score > c_score else "c")

def build_pyg_graph(sample_id, code):
    """Build PyG Data from tree-sitter call graph or token-based fallback."""
    if not code or not isinstance(code, str) or len(code.strip()) < 10:
        return None

    lang = _detect_lang(code)
    lang_key = {"c": "c", "python": "python", "java": "java"}.get(lang, "c")
    parser = _get_parser(lang_key)
    if parser is None:
        return _fallback_graph(code)

    try:
        tree = parser.parse(bytes(code, "utf-8"))
    except Exception:
        return _fallback_graph(code)

    root = tree.root_node

    # Extract functions and calls
    def_types = {
        "c": {"function_definition"},
        "cpp": {"function_definition"},
        "python": {"function_definition", "async_function_definition"},
        "java": {"method_declaration", "constructor_declaration"},
    }.get(lang_key, set())

    call_types = {
        "c": {"call_expression"},
        "cpp": {"call_expression"},
        "python": {"call"},
        "java": {"method_invocation"},
    }.get(lang_key, set())

    nodes = []  # [(name, start_line, end_line)]
    edges = []  # [(src_idx, dst_idx)]
    node_lines = []

    def _extract_name(node):
        for field in ("name", "function", "declarator"):
            child = node.child_by_field_name(field)
            if child:
                try:
                    return child.text.decode().strip().split("(")[0]
                except:
                    pass
        # Fallback: first identifier child
        for child in node.children:
            if child.type == "identifier":
                try:
                    return child.text.decode().strip()
                except:
                    pass
        return node.type

    def _extract_callee(node):
        for field in ("function", "name"):
            child = node.child_by_field_name(field)
            if child:
                try:
                    text = child.text.decode().strip()
                    if "." in text:
                        text = text.split(".")[-1]
                    return text.split("(")[0].strip()
                except:
                    pass
        return None

    def _walk(node, current_func=None, depth=0):
        if node.type in def_types and depth < 50:
            name = _extract_name(node)
            if name and len(name) > 1:
                current_func = len(nodes)
                nodes.append((name, node.start_point[0], node.end_point[0]))
                node_lines.append(node.start_point[0])

        if node.type in call_types and current_func is not None:
            callee = _extract_callee(node)
            if callee and len(callee) > 1:
                cid = len(nodes)
                nodes.append((callee, node.start_point[0], node.start_point[0]))
                node_lines.append(node.start_point[0])
                edges.append((current_func, cid))

        if node.child_count < 300:
            for child in node.children:
                _walk(child, current_func, depth + 1)

    _walk(root)

    if len(nodes) < 2:
        return _fallback_graph(code)

    # Build feature vectors: simple hash-based embedding of function names
    MAX_NODES = 300
    if len(nodes) > MAX_NODES:
        # Keep nodes with most connections
        deg = defaultdict(int)
        for s, d in edges:
            deg[s] += 1; deg[d] += 1
        keep = sorted(range(len(nodes)), key=lambda i: deg.get(i, 0), reverse=True)[:MAX_NODES]
        keep_set = set(keep)
        old_to_new = {old: new for new, old in enumerate(sorted(keep))}
        nodes = [nodes[i] for i in keep]
        node_lines = [node_lines[i] for i in keep]
        edges = [(old_to_new[s], old_to_new[d]) for s, d in edges if s in keep_set and d in keep_set]

    # Node features: function name hash (128-dim)
    x = torch.zeros(len(nodes), 128)
    for i, (name, _, _) in enumerate(nodes):
        h = abs(hash(name)) % (2**31)
        np.random.seed(h % (2**16))
        x[i] = torch.from_numpy(np.random.randn(128).astype(np.float32)) * 0.1

    # Edge index
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.zeros(2, 1, dtype=torch.long)

    data = Data(x=x, edge_index=edge_index)
    data.node_lines = torch.tensor(node_lines, dtype=torch.long)
    return data

def _fallback_graph(code):
    """Token-based fallback when tree-sitter fails. Tracks line numbers."""
    lines = code.split('\n')
    token_map = {}  # token_str -> first line number
    token_list = []  # ordered tokens
    for line_idx, line in enumerate(lines[:500], 1):
        for t in re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', str(line)):
            if t not in token_map:
                token_map[t] = line_idx
                token_list.append(t)
    if len(token_list) < 3:
        return None
    # Take up to 100 unique tokens
    tokens = token_list[:100]
    n = len(tokens)
    x = torch.zeros(n, 128)
    for i, t in enumerate(tokens):
        h = abs(hash(t)) % (2**31)
        np.random.seed(h % (2**16))
        x[i] = torch.from_numpy(np.random.randn(128).astype(np.float32)) * 0.1
    edges = [(i, i+1) for i in range(n-1)]
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    data = Data(x=x, edge_index=edge_index)
    data.node_lines = torch.tensor([token_map.get(t, 1) for t in tokens], dtype=torch.long)
    return data

if __name__ == "__main__":
    # Test
    code = """void foo() { bar(); baz(); }
    void bar() { qux(); }
    void baz() {}
    void qux() {}"""
    data = build_pyg_graph("test", code)
    print(f"Nodes: {data.x.shape[0]}, Edges: {data.edge_index.shape[1]}")
