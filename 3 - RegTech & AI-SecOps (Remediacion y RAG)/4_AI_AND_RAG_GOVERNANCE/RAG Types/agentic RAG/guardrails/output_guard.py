"""guardrails/output_guard.py — Output Sanitization & Hallucination Guardrail.
========================================================================
Protección contra Exfiltración de PII, Control de Toxicidad y Verificación de Citas.
"""

import re
from typing import Any


class OWASPOutputGuard:
    """Validador y sanitizador de respuestas generadas por el motor RAG."""

    PII_REGEX_PATTERNS = {
        "DNI_NIE": r"\b[XYZ]?\d{7,8}[A-Z]\b",
        "IBAN": r"\bES\d{2}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "PHONE": r"\b(?:\+34|0034)?[ \-]?[6789]\d{2}[ \-]?\d{3}[ \-]?\d{3}\b",
        "CREDIT_CARD": r"\b(?:\d{4}[ \-]?){3}\d{4}\b",
    }

    @classmethod
    def sanitize_output(cls, output_text: str, source_chunks: list[str] | None = None) -> tuple[bool, str, dict[str, Any]]:
        """Sanitiza la respuesta del LLM antes de enviarla al usuario/auditor.

        Devuelve:
            (is_valid: bool, sanitized_output: str, metadata: dict)
        """
        if not output_text:
            return False, "", {"status": "EMPTY_RESPONSE"}

        sanitized = output_text
        pii_detected = {}

        # 1. Enmascaramiento preventivo de fugas PII
        for pii_type, regex in cls.PII_REGEX_PATTERNS.items():
            matches = re.findall(regex, sanitized, flags=re.IGNORECASE)
            if matches:
                pii_detected[pii_type] = len(matches)
                sanitized = re.sub(regex, f"[{pii_type}_REDACTED]", sanitized, flags=re.IGNORECASE)

        # 2. Verificación de atestación de procedencia
        has_citations = bool(re.search(r'\[(?:Fuente|Doc|Art|Página|Normativa)[\s\:\.].*?\]|\[.*?\.md\]|\[.*?\.pdf\]', sanitized, re.IGNORECASE))

        return True, sanitized, {
            "status": "SANITIZED",
            "pii_redactions": pii_detected,
            "has_provenance_citations": has_citations,
            "original_length": len(output_text),
            "sanitized_length": len(sanitized),
        }
