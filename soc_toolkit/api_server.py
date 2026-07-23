"""
Enterprise Production REST API Server for SOC Toolkit
Provides high-performance RESTful JSON endpoints for enterprise SIEMs, SOAR platforms, and automation bots.
"""

import json
import http.server
import socketserver
import urllib.parse
from typing import Dict, Any

from .core import SOCToolkit
from .playbook import PlaybookGenerator
from .triage import LogTriageEngine
from .compliance import ComplianceEngine
from .osint import OSINTLinksGenerator


class SOCAPIServerHandler(http.server.SimpleHTTPRequestHandler):
    """Enterprise REST API HTTP Handler"""

    soc_engine = SOCToolkit()
    triage_engine = LogTriageEngine(soc_engine)

    def _send_json(self, data: Dict[str, Any], status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/v1/health":
            self._send_json({"status": "HEALTHY", "service": "SOC Toolkit REST API", "version": "5.0.0"})
        elif parsed.path == "/api/v1/providers":
            self._send_json(self.soc_engine.get_provider_status())
        else:
            self._send_json({"error": "Endpoint not found"}, status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Invalid JSON body"}, status=400)
            return

        if parsed.path == "/api/v1/lookup":
            ioc = body.get("ioc")
            if not ioc:
                self._send_json({"error": "Missing 'ioc' field"}, status=400)
                return

            report = self.soc_engine.lookup(ioc)
            osint_links = OSINTLinksGenerator.get_links(report.ioc, report.ioc_type)

            self._send_json({
                "ioc": report.ioc,
                "type": report.ioc_type.value,
                "overall_threat_level": report.overall_threat_level.value,
                "summary": report.summary,
                "osint_links": osint_links,
                "results": [
                    {
                        "source": r.source,
                        "found": r.found,
                        "threat_level": r.threat_level.value,
                        "response_time": r.response_time
                    }
                    for r in report.results
                ]
            })

        elif parsed.path == "/api/v1/compliance":
            ioc = body.get("ioc")
            if not ioc:
                self._send_json({"error": "Missing 'ioc' field"}, status=400)
                return
            report = self.soc_engine.lookup(ioc)
            comp = ComplianceEngine.evaluate_compliance(report.ioc, report.ioc_type, report.overall_threat_level)
            self._send_json(comp)

        else:
            self._send_json({"error": "Endpoint not found"}, status=404)


def start_api_server(port: int = 8000):
    """Start production REST API server"""
    server = socketserver.TCPServer(("0.0.0.0", port), SOCAPIServerHandler)
    print(f"🚀 Enterprise SOC Toolkit REST API running on http://0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping REST API Server...")
        server.shutdown()
