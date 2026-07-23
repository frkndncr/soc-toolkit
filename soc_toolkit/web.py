"""
Web Dashboard & GUI Server for SOC Toolkit
Provides a modern, high-tech dark-mode Web UI powered by Python's built-in http.server.
"""

import json
import http.server
import socketserver
import threading
import urllib.parse
from typing import Dict, Any

from .core import SOCToolkit
from .enums import IOCType
from .osint import OSINTLinksGenerator
from .playbook import PlaybookGenerator
from .whitelist import WhitelistFilter


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SOC Toolkit Workbench</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-card: #131a29;
            --bg-hover: #1c263b;
            --text-main: #f0f4fc;
            --text-dim: #8a99b5;
            --accent-blue: #00d2ff;
            --accent-green: #00e676;
            --accent-red: #ff1744;
            --accent-yellow: #ffea00;
            --border-color: #1e2d4a;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            line-height: 1.6;
            padding: 20px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 24px;
        }
        .header h1 {
            font-size: 24px;
            color: var(--accent-blue);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .search-box {
            display: flex;
            gap: 12px;
            margin-bottom: 24px;
        }
        .search-box input {
            flex: 1;
            padding: 14px 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background: var(--bg-card);
            color: #fff;
            font-size: 16px;
            font-family: 'JetBrains Mono', monospace;
        }
        .search-box button {
            padding: 14px 28px;
            border-radius: 8px;
            border: none;
            background: linear-gradient(135deg, #00d2ff, #0072ff);
            color: #fff;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .search-box button:hover { opacity: 0.9; transform: translateY(-1px); }
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            padding: 24px;
            margin-bottom: 24px;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-CRITICAL { background: rgba(255,23,68,0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .badge-HIGH { background: rgba(255,145,0,0.2); color: #ff9100; border: 1px solid #ff9100; }
        .badge-MEDIUM { background: rgba(255,234,0,0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .badge-CLEAN { background: rgba(0,230,118,0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }
        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th { color: var(--text-dim); font-size: 13px; font-weight: 600; text-transform: uppercase; }
        .links-grid { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; }
        .links-grid a {
            padding: 6px 14px;
            background: var(--bg-hover);
            color: var(--accent-blue);
            text-decoration: none;
            border-radius: 6px;
            font-size: 13px;
            border: 1px solid var(--border-color);
        }
        .links-grid a:hover { background: var(--accent-blue); color: #000; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SOC Toolkit Web Workbench</h1>
        <span style="color: var(--text-dim);">v3.0.0 Enterprise</span>
    </div>

    <div class="search-box">
        <input type="text" id="iocInput" placeholder="Enter IP, Domain, Hash, or URL (e.g. 185.220.101.45)...">
        <button onclick="performLookup()">Analyze IOC</button>
    </div>

    <div id="resultsArea"></div>

    <script>
        async function performLookup() {
            const ioc = document.getElementById('iocInput').value.trim();
            if (!ioc) return;
            const area = document.getElementById('resultsArea');
            area.innerHTML = '<div class="card">🔍 Querying 35+ Threat Intel Sources... Please wait...</div>';

            try {
                const res = await fetch('/api/lookup?ioc=' + encodeURIComponent(ioc));
                const data = await res.json();
                
                let html = `
                    <div class="card">
                        <div style="display:flex; justify-between; align-items:center;">
                            <h2>IOC: <span style="font-family: monospace; color: var(--accent-blue);">${data.ioc}</span></h2>
                            <span class="badge badge-${data.overall_threat_level}">${data.overall_threat_level}</span>
                        </div>
                        <p style="margin-top: 10px; color: var(--text-dim);">${data.summary}</p>
                    </div>
                `;

                if (data.osint_links) {
                    html += `<div class="card"><h3>🔗 Quick OSINT Links</h3><div class="links-grid">`;
                    for (const [name, url] of Object.entries(data.osint_links)) {
                        html += `<a href="${url}" target="_blank">${name} ↗</a>`;
                    }
                    html += `</div></div>`;
                }

                if (data.results) {
                    html += `<div class="card"><h3>🔎 Source Findings</h3><table>
                        <thead><tr><th>Source</th><th>Found</th><th>Threat</th><th>Response Time</th></tr></thead><tbody>`;
                    for (const r of data.results) {
                        html += `<tr>
                            <td><strong>${r.source}</strong></td>
                            <td>${r.found ? '✅ Yes' : '⚪ No'}</td>
                            <td><span class="badge badge-${r.threat_level}">${r.threat_level}</span></td>
                            <td>${r.response_time ? r.response_time.toFixed(2) + 's' : '-'}</td>
                        </tr>`;
                    }
                    html += `</tbody></table></div>`;
                }

                area.innerHTML = html;
            } catch (err) {
                area.innerHTML = `<div class="card" style="color: var(--accent-red);">Error performing lookup: ${err}</div>`;
            }
        }
    </script>
</body>
</html>
"""


class SOCWebHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler for SOC Toolkit Web UI"""
    
    soc_engine = SOCToolkit()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode('utf-8'))
        elif parsed.path == "/api/lookup":
            params = urllib.parse.parse_qs(parsed.query)
            ioc = params.get("ioc", [""])[0]
            if not ioc:
                self.send_error(400, "Missing ioc parameter")
                return

            report = self.soc_engine.lookup(ioc)
            osint_links = OSINTLinksGenerator.get_links(report.ioc, report.ioc_type)

            data = {
                "ioc": report.ioc,
                "ioc_type": report.ioc_type.value,
                "overall_threat_level": report.overall_threat_level.value.upper(),
                "summary": report.summary,
                "osint_links": osint_links,
                "results": [
                    {
                        "source": r.source,
                        "found": r.found,
                        "threat_level": r.threat_level.value.upper(),
                        "response_time": r.response_time,
                        "error": r.error
                    }
                    for r in report.results
                ]
            }

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode('utf-8'))
        else:
            self.send_error(404, "File Not Found")


def start_web_server(port: int = 8080):
    """Start local web GUI server"""
    server = socketserver.TCPServer(("127.0.0.1", port), SOCWebHandler)
    print(f"🚀 SOC Toolkit Web GUI running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Web Server...")
        server.shutdown()
