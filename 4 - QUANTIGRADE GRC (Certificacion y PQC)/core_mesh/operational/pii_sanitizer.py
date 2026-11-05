from __future__ import annotations
import re
from typing import Dict, Any, Tuple

class PIISanitizer:
    """Real-time detection and masking of Spanish and European Personally Identifiable Information (PII)."""

    PATTERNS = {
        "DNI_NIE": r"\b[XYZxyz]?\d{7,8}[A-Za-z]\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
        "IBAN": r"\bES\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}\b",
        "PHONE": r"\b(\+34|0034)?[ -]?[6789]\d{2}[ -]?\d{3}[ -]?\d{3}\b",
        "CREDIT_CARD": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
    }

    @classmethod
    def sanitize(cls, text: str) -> Tuple[str, Dict[str, int]]:
        sanitized = text
        stats: Dict[str, int] = {}
        for pii_type, pattern in cls.PATTERNS.items():
            matches = re.findall(pattern, sanitized)
            if matches:
                stats[pii_type] = len(matches)
                sanitized = re.sub(pattern, f"[REDACTED_{pii_type}]", sanitized)
        return sanitized, stats
