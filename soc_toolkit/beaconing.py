"""
C2 Network Beaconing & Jitter Calculator for SOC Toolkit
Analyzes network connection timestamps and calculates delta variance to pinpoint periodic C2 beaconing.
"""

import math
from typing import Dict, Any, List


class BeaconingCalculator:
    """Calculate network connection interval delta variance to detect C2 Beaconing"""

    @classmethod
    def calculate_beaconing(cls, timestamps: List[float]) -> Dict[str, Any]:
        """
        Calculate beaconing score based on connection interval deltas.
        """
        if len(timestamps) < 3:
            return {"is_beaconing": False, "score": 0, "reason": "Insufficient timestamp data (min 3 required)"}

        deltas = []
        for i in range(1, len(timestamps)):
            deltas.append(abs(timestamps[i] - timestamps[i-1]))

        mean_delta = sum(deltas) / len(deltas)
        variance = sum((x - mean_delta) ** 2 for x in deltas) / len(deltas)
        std_dev = math.sqrt(variance)

        # Low std_dev relative to mean indicates fixed-interval periodic C2 beaconing
        is_beaconing = std_dev < (mean_delta * 0.15)

        return {
            "is_beaconing": is_beaconing,
            "mean_interval_seconds": round(mean_delta, 2),
            "std_deviation": round(std_dev, 2),
            "jitter_percent": round((std_dev / mean_delta) * 100, 2) if mean_delta > 0 else 0,
            "assessment": "CRITICAL - Periodic C2 Heartbeat Beaconing Detected" if is_beaconing else "NORMAL - Variable Traffic"
        }
