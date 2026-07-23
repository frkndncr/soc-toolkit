"""
Interactive Threat Graph Visualizer for SOC Toolkit
Generates interactive node-edge relationship graphs (SVG/HTML) mapping IOCs to threat sources, malware families, and risk scores.
"""

import json
from typing import Dict, Any, List


class ThreatGraphVisualizer:
    """Generate HTML/SVG Threat Graph visualizations"""

    @classmethod
    def generate_html_graph(cls, ioc: str, threat_level: str, findings: List[Dict[str, Any]]) -> str:
        """
        Generates standalone HTML visualization of threat relationship graph using Vis.js.
        """
        nodes = [{"id": 1, "label": ioc, "color": "#ff1744" if "CRITICAL" in threat_level.upper() else "#00d2ff", "shape": "diamond", "size": 30}]
        edges = []

        node_id = 2
        for f in findings:
            source_name = f.get("source", "Source")
            nodes.append({"id": node_id, "label": source_name, "color": "#1c263b", "shape": "box"})
            edges.append({"from": 1, "to": node_id})
            node_id += 1

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Threat Relationship Graph - {ioc}</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{ background: #0a0e17; color: #fff; font-family: sans-serif; margin: 0; padding: 20px; }}
        #network {{ width: 100%; height: 600px; border: 1px solid #1e2d4a; border-radius: 12px; background: #131a29; }}
    </style>
</head>
<body>
    <h2>🕸️ Threat Relationship Graph: <span style="color: #00d2ff;">{ioc}</span></h2>
    <div id="network"></div>
    <script>
        var nodes = new vis.DataSet({json.dumps(nodes)});
        var edges = new vis.DataSet({json.dumps(edges)});
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{ nodes: {{ font: {{ color: '#ffffff' }} }}, edges: {{ color: '#00d2ff' }} }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>"""
        return html

    @classmethod
    def export_graph(cls, ioc: str, threat_level: str, findings: List[Dict[str, Any]], filepath: str):
        """Save HTML Threat Graph to file"""
        html = cls.generate_html_graph(ioc, threat_level, findings)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
