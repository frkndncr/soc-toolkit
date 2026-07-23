"""
Executive Incident Response Report & Ticket Generator for SOC Toolkit v7.0.0
Generates 1-click professional Incident Tickets for Jira, ServiceNow, MSSP Clients, and Executive C-Suite.
"""

from datetime import datetime
from typing import Dict, Any, List
from .enums import IOCType, ThreatLevel, IOCReport
from .playbook import PlaybookGenerator


class ExecutiveReportGenerator:
    """Generate professional Incident Tickets and Executive Security Reports"""

    @classmethod
    def generate_incident_ticket(cls, report: IOCReport, ticket_id: str = "INC-9901") -> Dict[str, str]:
        """
        Generate Markdown and Jira/ServiceNow compatible ticket description.
        """
        playbook = PlaybookGenerator.generate(report.ioc, report.ioc_type, report.overall_threat_level)

        markdown_ticket = f"""# 🚨 SECURITY INCIDENT TICKET: {ticket_id}

**Severity**: `{report.overall_threat_level.value.upper()}`
**Target IOC**: `{report.ioc}` ({report.ioc_type.value.upper()})
**Detected At**: {report.timestamp}

---

## 📋 Executive Summary
{report.summary}

---

## 🛡️ Immediate Containment Playbook
{playbook.to_markdown()}

---

## 🔎 Threat Intelligence Findings
"""
        for r in report.results:
            if r.found:
                markdown_ticket += f"- **{r.source}**: {r.threat_level.value.upper()} | Data: {r.data}\n"

        jira_ticket = f"""h1. 🚨 SECURITY INCIDENT TICKET: {ticket_id}
*Severity*: {report.overall_threat_level.value.upper()}
*Target IOC*: {report.ioc}
*Detected At*: {report.timestamp}

h2. Executive Summary
{report.summary}

h2. Playbook Actions
* Execute Containment: Firewall Drop & Host Isolation
"""

        return {
            "ticket_id": ticket_id,
            "markdown": markdown_ticket,
            "jira_format": jira_ticket,
            "servicenow_summary": f"[{report.overall_threat_level.value.upper()}] Security Incident - Malicious IOC {report.ioc} detected in SOC telemetry."
        }
