"""
Global Multi-Language Executive Report Engine for SOC Toolkit
Translates Executive Summaries and Containment Playbooks into English, Turkish, German, French, Spanish, and Japanese.
"""

from typing import Dict, Any


MESSAGES = {
    "en": {"title": "SECURITY REPORT", "risk": "Risk Score", "action": "Immediate Containment Required"},
    "tr": {"title": "GÜVENLİK RAPORU", "risk": "Risk Skoru", "action": "Acil İzolasyon ve Engelleme Gerekli"},
    "de": {"title": "SICHERHEITSBERICHT", "risk": "Risikobewertung", "action": "Sofortige Eindämmung erforderlich"},
    "fr": {"title": "RAPPORT DE SÉCURITÉ", "risk": "Score de Risque", "action": "Confinement immédiat requis"},
    "es": {"title": "INFORME DE SEGURIDAD", "risk": "Puntuación de Riesgo", "action": "Contención inmediata requerida"},
    "ja": {"title": "セキュリティレポート", "risk": "リスクスコア", "action": "緊急隔離とブロックが必要"}
}


class GlobalI18nEngine:
    """Multi-language report translation engine for international MSSPs"""

    @classmethod
    def format_report(cls, ioc: str, threat_level: str, lang: str = "en") -> Dict[str, str]:
        lang_code = lang.lower() if lang.lower() in MESSAGES else "en"
        msg = MESSAGES[lang_code]

        return {
            "language": lang_code,
            "title": f"{msg['title']}: {ioc}",
            "summary": f"{msg['risk']}: {threat_level.upper()} | {msg['action']} for target {ioc}."
        }
