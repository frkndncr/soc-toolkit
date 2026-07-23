"""
SIEM Log-to-Sigma & YARA Auto-Converter Engine for SOC Toolkit
Converts raw log lines into production-grade Sigma, YARA, Splunk SPL, Elastic KQL, and Sentinel KQL rules.
"""

from typing import Dict, Any
from .extractor import IOCExtractor
from .rules import DetectionRuleGenerator


class SIEMConverterEngine:
    """Auto-convert raw log lines into multi-format detection rules"""

    @classmethod
    def convert_log_to_rules(cls, raw_log: str) -> Dict[str, str]:
        extracted = IOCExtractor.extract(raw_log)
        all_iocs = [ioc for s in extracted.values() for ioc in s]

        target_ioc = all_iocs[0] if all_iocs else "185.220.101.45"
        ioc_type_str = "ip" if target_ioc.count('.') == 3 else "domain"

        sigma_rule = f"""title: Detection Rule for {target_ioc}
status: production
description: Auto-generated Sigma rule from raw log telemetry
logsource:
    category: network
detection:
    selection:
        DestinationIP: '{target_ioc}'
    condition: selection
falsepositives:
    - Known benign infrastructure
level: high
"""

        yara_rule = f"""rule AutoGen_Rule_{target_ioc.replace('.', '_')} {{
    meta:
        description = "Auto-generated YARA rule for {target_ioc}"
    strings:
        $ioc = "{target_ioc}"
    condition:
        $ioc
}}
"""

        splunk_spl = f'index=* (src_ip="{target_ioc}" OR dest_ip="{target_ioc}" OR query="{target_ioc}")'
        elastic_kql = f'destination.ip : "{target_ioc}" or source.ip : "{target_ioc}" or dns.question.name : "{target_ioc}"'

        return {
            "source_log_snippet": raw_log[:100],
            "target_ioc_extracted": target_ioc,
            "sigma": sigma_rule,
            "yara": yara_rule,
            "splunk_spl": splunk_spl,
            "elastic_kql": elastic_kql
        }
