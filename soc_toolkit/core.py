"""
Core SOC Toolkit Engine v3.0.0
"""

import concurrent.futures
from datetime import datetime
from typing import Optional, List

from .enums import IOCType, ThreatLevel, LookupResult, IOCReport
from .detectors import IOCDetector
from .config import Config
from .providers import ALL_PROVIDERS
from .whitelist import WhitelistFilter


class SOCToolkit:
    """Main SOC Toolkit engine for IOC lookups"""
    
    def __init__(self, providers=None):
        if providers is None:
            providers = ALL_PROVIDERS
            
        self.providers = [p() for p in providers]
        
    def lookup(self, ioc: str, ioc_type: Optional[IOCType] = None) -> IOCReport:
        """
        Perform comprehensive IOC lookup across all providers
        """
        # Clean input & refang
        ioc = IOCDetector.refang(ioc.strip())
        
        # Auto-detect IOC type if not provided
        if ioc_type is None:
            ioc_type = IOCDetector.detect(ioc)
            
        if ioc_type == IOCType.UNKNOWN:
            return IOCReport(
                ioc=ioc,
                ioc_type=ioc_type,
                timestamp=datetime.now().isoformat(),
                summary="❌ Could not detect IOC type"
            )
            
        # Check Whitelist / False Positive Filter first
        whitelist_eval = WhitelistFilter.evaluate(ioc, ioc_type.value)

        # Filter applicable providers
        applicable_providers = [
            p for p in self.providers 
            if ioc_type in p.supported_types
        ]
        
        results = []
        
        # Parallel lookup across providers
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            future_to_provider = {
                executor.submit(p.lookup, ioc, ioc_type): p 
                for p in applicable_providers
            }
            
            for future in concurrent.futures.as_completed(future_to_provider):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    provider = future_to_provider[future]
                    results.append(LookupResult(
                        source=provider.name,
                        found=False,
                        error=str(e)
                    ))
        
        # Calculate overall threat level
        overall_threat = self._calculate_overall_threat(results)
        
        # Override overall threat level if Whitelist Filter matched known benign infrastructure
        if whitelist_eval.get("is_benign"):
            overall_threat = ThreatLevel.CLEAN

        # Generate summary
        summary = self._generate_summary(results, overall_threat, whitelist_eval)
        
        return IOCReport(
            ioc=ioc,
            ioc_type=ioc_type,
            timestamp=datetime.now().isoformat(),
            results=results,
            overall_threat_level=overall_threat,
            summary=summary
        )
        
    def _calculate_overall_threat(self, results: List[LookupResult]) -> ThreatLevel:
        """Calculate overall threat level from all results"""
        threat_scores = {
            ThreatLevel.CLEAN: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
            ThreatLevel.UNKNOWN: -1
        }
        
        max_score = -1
        for result in results:
            if result.found and result.threat_level != ThreatLevel.UNKNOWN:
                score = threat_scores.get(result.threat_level, -1)
                max_score = max(max_score, score)
                
        for level, score in threat_scores.items():
            if score == max_score:
                return level
                
        return ThreatLevel.UNKNOWN
        
    def _generate_summary(self, results: List[LookupResult], 
                          overall_threat: ThreatLevel,
                          whitelist_eval: dict = None) -> str:
        """Generate human-readable summary"""
        whitelist_eval = whitelist_eval or {}
        
        if whitelist_eval.get("is_benign"):
            summary = f"🟢 CLEAN - {whitelist_eval.get('reason')}\n"
            summary += "🛡️ False Positive Filter: Verified Legitimate Infrastructure"
            return summary

        threat_descriptions = {
            ThreatLevel.CLEAN: "✅ CLEAN - No threats detected",
            ThreatLevel.LOW: "🟢 LOW RISK - Minimal threat indicators",
            ThreatLevel.MEDIUM: "🟡 MEDIUM RISK - Exercise caution",
            ThreatLevel.HIGH: "🟠 HIGH RISK - Suspicious activity detected",
            ThreatLevel.CRITICAL: "🔴 CRITICAL - Known malicious indicator!",
            ThreatLevel.UNKNOWN: "⚪ UNKNOWN - Insufficient data"
        }
        
        found_count = sum(1 for r in results if r.found)
        malicious_count = sum(1 for r in results if r.found and 
                            r.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
        
        summary = f"{threat_descriptions.get(overall_threat, 'Unknown')}\n"
        summary += f"📊 Found in {found_count}/{len(results)} sources"
        
        if malicious_count > 0:
            summary += f" | ⚠️  {malicious_count} sources flagged as malicious"
            
        return summary
    
    def get_provider_status(self) -> dict:
        """Get status of all providers"""
        return {
            p.name: {
                "enabled": True,
                "requires_api_key": p.requires_api_key,
                "has_api_key": not p.requires_api_key or bool(
                    getattr(Config, f"{p.name.upper().replace(' ', '_')}_API_KEY", None)
                ),
                "supported_types": [t.value for t in p.supported_types]
            }
            for p in self.providers
        }
