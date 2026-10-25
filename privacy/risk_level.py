# Lookup Table: purpose -> (ризик за джерелом, ризик за замовчуванням для інших джерел)
_RISK_TABLE = {
    "marketing": ({"api": "high", "ui": "low"}, "medium"),
    "analytics": ({"api": "medium", "ui": "low"}, "medium"),
    "personalization": ({"api": "medium", "ui": "low"}, "high"),
    "third_party": ({}, "high"),
}


def consent_risk_level(purpose, source):
    """Оцінка ризику згоди за призначенням та джерелом (Data-Driven версія)."""
    by_source, default = _RISK_TABLE.get(purpose, ({}, "unknown"))
    return by_source.get(source, default)
