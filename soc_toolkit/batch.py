"""
Multithreaded Batch Log File Scanner & IOC Extractor for SOC Toolkit
"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Any, List

from .extractor import IOCExtractor
from .core import SOCToolkit


class BatchScanner:
    """Parallel Batch File IOC Extractor & Scanner"""

    @classmethod
    def scan_file(cls, filepath: str, max_workers: int = 5) -> Dict[str, Any]:
        path = Path(filepath)
        if not path.exists():
            return {
                "error": f"File not found: {filepath}",
                "filepath": filepath,
                "total_extracted": 0,
                "results": []
            }

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return {
                "error": f"Failed to read file: {str(e)}",
                "filepath": filepath,
                "total_extracted": 0,
                "results": []
            }

        extracted = IOCExtractor.extract_all(content)
        all_iocs = list(set(extracted.get("ips", []) + extracted.get("domains", []) + extracted.get("hashes", []) + extracted.get("urls", [])))

        if not all_iocs:
            return {
                "filepath": filepath,
                "file_size_bytes": path.stat().st_size,
                "total_extracted": 0,
                "clean_count": 0,
                "high_risk_count": 0,
                "critical_count": 0,
                "results": []
            }

        soc = SOCToolkit()
        results = []

        def lookup_worker(ioc_str: str):
            try:
                rep = soc.lookup(ioc_str)
                return {
                    "ioc": rep.ioc,
                    "type": rep.ioc_type.value,
                    "threat_level": rep.overall_threat_level.value,
                    "risk_score": rep.overall_risk_score
                }
            except Exception:
                return {
                    "ioc": ioc_str,
                    "type": "UNKNOWN",
                    "threat_level": "UNKNOWN",
                    "risk_score": 0
                }

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(lookup_worker, all_iocs))

        clean_cnt = sum(1 for r in results if r["threat_level"] in ("CLEAN", "LOW"))
        high_cnt = sum(1 for r in results if r["threat_level"] in ("MEDIUM", "HIGH"))
        critical_cnt = sum(1 for r in results if r["threat_level"] == "CRITICAL")

        return {
            "filepath": filepath,
            "file_size_bytes": path.stat().st_size,
            "total_extracted": len(all_iocs),
            "clean_count": clean_cnt,
            "high_risk_count": high_cnt,
            "critical_count": critical_cnt,
            "results": results
        }
