#!/usr/bin/python3
"""Generate an interactive HTML visualization of a CPG .bin file."""

import json
import sys
from collections import Counter
from pathlib import Path

from scubatrace import cpg


def load_cpg(bin_path: str) -> cpg.Cpg:
    print(f"Loading CPG from {bin_path}...")
    return cpg.load(bin_path)


def build_call_graph(cpg_obj: cpg.Cpg) -> dict:
    """Extract method-to-method call relationships.

    CALL edges go from CALL node (callsite) to METHOD node (callee).
    The caller is the METHOD that CONTAINS the CALL node.
    """
    methods = cpg_obj.nodes_by_label("METHOD")
    method_index = {m.id: i for i, m in enumerate(methods)}

    nodes = []
    for m in methods:
        name = m.properties.get("NAME") or m.properties.get("FULL_NAME") or "?"
        full_name = m.properties.get("FULL_NAME") or ""
        filename = m.properties.get("FILENAME") or ""
        line = m.properties.get("LINE_NUMBER") or 0
        nodes.append({
            "id": method_index[m.id],
            "label": name,
            "full_name": full_name,
            "filename": filename,
            "line": line,
            "is_external": m.properties.get("IS_EXTERNAL", False),
        })

    # Build caller index: for each CALL node, find enclosing METHOD via CONTAINS
    call_to_caller: dict = {}
    for edge in cpg_obj.edges:
        if edge.label == "CONTAINS":
            dst_node = cpg_obj.nodes.get(edge.dst)
            if dst_node is not None and dst_node.label == "CALL":
                src_node = cpg_obj.nodes.get(edge.src)
                if src_node is not None and src_node.label == "METHOD":
                    call_to_caller[edge.dst] = src_node

    # Build METHOD-to-METHOD edges from CALL edges
    edges = []
    edge_set = set()
    for edge in cpg_obj.edges:
        if edge.label == "CALL":
            callsite_id = edge.src
            callee_id = edge.dst
            callee = method_index.get(callee_id)
            if callee is None:
                continue
            caller_method = call_to_caller.get(callsite_id)
            if caller_method is None:
                continue
            caller = method_index.get(caller_method.id)
            if caller is None:
                continue
            key = (caller, callee)
            if key not in edge_set:
                edge_set.add(key)
                edges.append({"from": caller, "to": callee})

    return {"nodes": nodes, "edges": edges}


def build_file_summary(cpg_obj: cpg.Cpg) -> list[dict]:
    """Build per-file summary of methods and call counts."""
    files = cpg_obj.nodes_by_label("FILE")
    methods = cpg_obj.nodes_by_label("METHOD")

    file_methods: dict[str, list] = {}
    for m in methods:
        fname = m.properties.get("FILENAME") or "(unknown)"
        file_methods.setdefault(fname, []).append(m)

    result = []
    for f in files:
        name = f.properties.get("NAME") or "?"
        result.append({
            "name": name,
            "method_count": len(file_methods.get(name, [])),
        })
    return sorted(result, key=lambda x: x["method_count"], reverse=True)


def build_node_stats(cpg_obj: cpg.Cpg) -> dict[str, int]:
    """Count nodes by label."""
    return dict(Counter(n.label for n in cpg_obj.nodes.values()))


def build_edge_stats(cpg_obj: cpg.Cpg) -> dict[str, int]:
    """Count edges by label."""
    return dict(Counter(e.label for e in cpg_obj.edges))


def generate_html(call_graph: dict, file_summary: list[dict],
                  node_stats: dict, edge_stats: dict,
                  total_nodes: int, total_edges: int,
                  output_path: str) -> None:
    """Generate a self-contained interactive HTML file."""

    call_graph_json = json.dumps(call_graph)
    file_summary_json = json.dumps(file_summary)
    node_stats_json = json.dumps(node_stats)
    edge_stats_json = json.dumps(edge_stats)

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CPG Visualization</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/vis-network.min.js">
</script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/vis-network.min.css" rel="stylesheet">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #1a1a2e; color: #e0e0e0; height: 100vh; display: flex; flex-direction: column; }}

header {{ background: #16213e; padding: 12px 24px; display: flex; align-items: center; gap: 24px;
          border-bottom: 1px solid #0f3460; flex-shrink: 0; }}
header h1 {{ font-size: 20px; color: #e94560; }}
header .stats {{ display: flex; gap: 16px; font-size: 13px; }}
header .stats span {{ background: #0f3460; padding: 4px 10px; border-radius: 12px; }}

.tabs {{ display: flex; background: #16213e; padding: 0 24px; gap: 0; flex-shrink: 0; }}
.tab {{ padding: 10px 20px; cursor: pointer; border: none; background: none; color: #888;
        font-size: 14px; border-bottom: 2px solid transparent; transition: all 0.2s; }}
.tab:hover {{ color: #e0e0e0; }}
.tab.active {{ color: #e94560; border-bottom-color: #e94560; }}

.controls {{ background: #16213e; padding: 8px 24px; display: flex; gap: 12px; align-items: center;
             border-bottom: 1px solid #0f3460; flex-shrink: 0; }}
.controls input {{ padding: 6px 12px; border: 1px solid #0f3460; border-radius: 6px;
                   background: #1a1a2e; color: #e0e0e0; font-size: 13px; width: 280px; }}
.controls input:focus {{ outline: none; border-color: #e94560; }}
.controls button {{ padding: 6px 16px; background: #e94560; color: white; border: none;
                    border-radius: 6px; cursor: pointer; font-size: 13px; }}
.controls button:hover {{ background: #d63851; }}
.controls label {{ font-size: 13px; display: flex; align-items: center; gap: 6px; cursor: pointer; }}

.panels {{ flex: 1; display: flex; overflow: hidden; }}
.panel {{ display: none; flex: 1; }}
.panel.active {{ display: flex; }}

#callgraph {{ flex: 1; }}

#detail-panel {{ width: 360px; background: #16213e; border-left: 1px solid #0f3460; display: none;
                 flex-direction: column; overflow-y: auto; padding: 16px; font-size: 13px; }}
#detail-panel.visible {{ display: flex; }}
#detail-panel h3 {{ color: #e94560; margin-bottom: 8px; }}
#detail-panel .prop {{ margin: 4px 0; }}
#detail-panel .prop-key {{ color: #888; }}
#detail-panel .prop-val {{ color: #a8d8ea; }}

#overview {{ padding: 24px; overflow-y: auto; }}
#overview table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
#overview th {{ text-align: left; padding: 8px 12px; background: #0f3460; color: #e94560;
                position: sticky; top: 0; }}
#overview td {{ padding: 6px 12px; border-bottom: 1px solid #0f3460; }}
#overview tr:hover td {{ background: rgba(233,69,96,0.1); }}

.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
               gap: 12px; margin-bottom: 24px; }}
.stat-card {{ background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 16px; }}
.stat-card .stat-label {{ font-size: 12px; color: #888; text-transform: uppercase; }}
.stat-card .stat-value {{ font-size: 24px; color: #e94560; font-weight: bold; }}

/* vis.js overrides */
.vis-network:focus {{ outline: none; }}
.vis-tooltip {{ position: absolute; background: #16213e; border: 1px solid #e94560; color: #e0e0e0;
                padding: 8px 12px; border-radius: 6px; font-size: 12px; pointer-events: none;
                z-index: 1000; max-width: 400px; }}
</style>
</head>
<body>

<header>
  <h1>CPG Visualization</h1>
  <div class="stats">
    <span>Nodes: {total_nodes:,}</span>
    <span>Edges: {total_edges:,}</span>
    <span>Methods: {call_graph['nodes'].__len__():,}</span>
    <span>Calls: {call_graph['edges'].__len__():,}</span>
  </div>
</header>

<div class="tabs">
  <button class="tab active" onclick="switchTab('callgraph-tab')">Call Graph</button>
  <button class="tab" onclick="switchTab('overview-tab')">Files & Methods</button>
  <button class="tab" onclick="switchTab('stats-tab')">Statistics</button>
</div>

<div class="controls" id="callgraph-controls">
  <input type="text" id="search" placeholder="Search function name (regex)..." oninput="filterGraph()">
  <button onclick="resetGraph()">Reset View</button>
  <button onclick="fitGraph()">Fit</button>
  <label><input type="checkbox" id="showExternal" onchange="filterGraph()"> Show external</label>
  <label><input type="checkbox" id="physicsToggle" checked onchange="togglePhysics()"> Physics</label>
</div>

<div class="panels">
  <!-- Call Graph Panel -->
  <div class="panel active" id="callgraph-tab" style="display: flex;">
    <div id="callgraph"></div>
    <div id="detail-panel"></div>
  </div>

  <!-- Files Panel -->
  <div class="panel" id="overview-tab">
    <div id="overview"></div>
  </div>

  <!-- Stats Panel -->
  <div class="panel" id="stats-tab">
    <div id="overview-stats" style="padding:24px; overflow-y:auto; flex:1;"></div>
  </div>
</div>

<script>
const callGraphData = {call_graph_json};

const container = document.getElementById('callgraph');
const nodes = new vis.DataSet(callGraphData.nodes.map(n => ({{
  ...n,
  color: n.is_external ? '#555' : '#e94560',
  shape: n.is_external ? 'dot' : 'dot',
  size: n.is_external ? 8 : 12,
  title: `<b>${{escape(n.label)}}</b><br>${{escape(n.full_name)}}<br>${{escape(n.filename)}}:${{n.line}}`,
}})));

const edges = new vis.DataSet(callGraphData.edges.map(e => ({{
  ...e,
  arrows: 'to',
  color: {{ color: '#0f3460', highlight: '#e94560' }},
  smooth: {{ type: 'curvedCW', roundness: 0.2 }},
}})));

const allNodes = new vis.DataSet(nodes.get());
const allEdges = new vis.DataSet(edges.get());

const data = {{ nodes, edges }};
const options = {{
  physics: {{
    solver: 'forceAtlas2Based',
    forceAtlas2Based: {{
      gravitationalConstant: -40,
      centralGravity: 0.005,
      springLength: 100,
      springConstant: 0.08,
      damping: 0.4,
    }},
    stabilization: {{ iterations: 100 }},
  }},
  interaction: {{
    tooltipDelay: 200,
    hover: true,
    navigationButtons: true,
    keyboard: true,
  }},
  layout: {{ improvedLayout: true }},
  edges: {{ width: 1 }},
}};

const network = new vis.Network(container, data, options);

network.on('click', function(params) {{
  if (params.nodes.length > 0) {{
    const nodeId = params.nodes[0];
    const node = nodes.get(nodeId);
    showDetail(node);
  }}
}});

network.on('deselectNode', function() {{
  document.getElementById('detail-panel').classList.remove('visible');
}});

function showDetail(node) {{
  const panel = document.getElementById('detail-panel');
  panel.classList.add('visible');
  panel.innerHTML = `
    <h3>${{escape(node.label)}}</h3>
    <div class="prop"><span class="prop-key">Full Name:</span> <span class="prop-val">${{escape(node.full_name)}}</span></div>
    <div class="prop"><span class="prop-key">File:</span> <span class="prop-val">${{escape(node.filename)}}</span></div>
    <div class="prop"><span class="prop-key">Line:</span> <span class="prop-val">${{node.line}}</span></div>
    <div class="prop"><span class="prop-key">External:</span> <span class="prop-val">${{node.is_external}}</span></div>
  `;
}}

function filterGraph() {{
  const query = document.getElementById('search').value;
  const showExt = document.getElementById('showExternal').checked;
  let regex;
  try {{ regex = query ? new RegExp(query, 'i') : null; }} catch(e) {{ return; }}

  const filteredNodes = allNodes.get().filter(n => {{
    if (!showExt && n.is_external) return false;
    if (!regex) return !n.is_external;
    return regex.test(n.label) || regex.test(n.full_name) || regex.test(n.filename);
  }});

  const filteredIds = new Set(filteredNodes.map(n => n.id));
  const filteredEdges = allEdges.get().filter(e =>
    filteredIds.has(e.from) && filteredIds.has(e.to)
  );

  nodes.clear();
  edges.clear();
  nodes.add(filteredNodes);
  edges.add(filteredEdges);
  network.fit({{ animation: true }});
}}

function resetGraph() {{
  document.getElementById('search').value = '';
  document.getElementById('showExternal').checked = false;
  nodes.clear();
  edges.clear();
  nodes.add(allNodes.get().filter(n => !n.is_external));
  edges.add(allEdges.get());
  network.fit({{ animation: true }});
}}

function fitGraph() {{
  network.fit({{ animation: true }});
}}

function togglePhysics() {{
  const enabled = document.getElementById('physicsToggle').checked;
  network.setOptions({{ physics: enabled }});
}}

function switchTab(tabId) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  const tabMap = {{ 'callgraph-tab': 0, 'overview-tab': 1, 'stats-tab': 2 }};
  document.querySelectorAll('.tab')[tabMap[tabId]].classList.add('active');
  document.getElementById(tabId).classList.add('active');
  if (tabId === 'callgraph-tab') {{
    document.getElementById('callgraph-controls').style.display = 'flex';
    setTimeout(() => network.fit(), 100);
  }} else {{
    document.getElementById('callgraph-controls').style.display = 'none';
  }}
}}

// Initialize: hide external nodes by default
filterGraph();

// Build file overview table
(function() {{
  const files = {file_summary_json};
  let html = '<table><thead><tr><th>File</th><th>Methods</th></tr></thead><tbody>';
  for (const f of files) {{
    html += `<tr><td>${{escape(f.name)}}</td><td>${{f.method_count}}</td></tr>`;
  }}
  html += '</tbody></table>';
  document.getElementById('overview').innerHTML = html;
}})();

// Build stats view
(function() {{
  const nodes = {node_stats_json};
  const edgeLabels = {edge_stats_json};
  let html = '<div class="stats-grid">';
  for (const [label, count] of Object.entries(nodes).sort((a,b) => b[1]-a[1])) {{
    html += `<div class="stat-card"><div class="stat-label">${{label}} nodes</div><div class="stat-value">${{count.toLocaleString()}}</div></div>`;
  }}
  html += '</div><h3 style="color:#e94560;margin-bottom:12px;">Edge Types</h3><div class="stats-grid">';
  for (const [label, count] of Object.entries(edgeLabels).sort((a,b) => b[1]-a[1])) {{
    html += `<div class="stat-card"><div class="stat-label">${{label}}</div><div class="stat-value">${{count.toLocaleString()}}</div></div>`;
  }}
  html += '</div>';
  document.getElementById('overview-stats').innerHTML = html;
}})();
</script>
</body>
</html>'''

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"HTML visualization written to: {output_path}")


def main():
    if len(sys.argv) < 2:
        bin_path = "./build/joern-cpg/cpg.bin"
    else:
        bin_path = sys.argv[1]

    output_path = sys.argv[2] if len(sys.argv) > 2 else bin_path.replace(".bin", ".html")

    cpg_obj = load_cpg(bin_path)

    print(f"Building call graph from {cpg_obj.node_count:,} nodes, {cpg_obj.edge_count:,} edges...")
    call_graph = build_call_graph(cpg_obj)
    print(f"  Methods: {len(call_graph['nodes']):,}, Calls: {len(call_graph['edges']):,}")

    file_summary = build_file_summary(cpg_obj)
    node_stats = build_node_stats(cpg_obj)
    edge_stats = build_edge_stats(cpg_obj)

    generate_html(call_graph, file_summary, node_stats, edge_stats,
                  cpg_obj.node_count, cpg_obj.edge_count, output_path)
    print("Done!")


if __name__ == "__main__":
    main()
