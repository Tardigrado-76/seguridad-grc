"""guardrails/input_guard.py — OWASP Top 10 for LLMs Input Guardrail.
================================================================
Prevención de Prompt Injection, Jailbreaks y Exfiltración de Instrucciones del Sistema.
"""

import re
from typing import Any


class OWASPInputGuard:
    """Interceptor perimetral de seguridad para prompts de entrada."""

    PROMPT_INJECTION_PATTERNS = [
        r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|directives)\b",
        r"(?i)\bolvida\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)\b",
        r"(?i)\byou\s+are\s+now\s+(?:a|an|in|dan|jailbreak)\b",
        r"(?i)\bahora\s+eres\s+(?:un|una|el\s+modo)\b",
        r"(?i)\b(?:reveal|show|display|print|dump)\s+(?:the\s+)?(?:system\s+prompt|base\s+instructions|secret\s+key)\b",
        r"(?i)\b(?:muestra|revela|imprime)\s+(?:el\s+prompt\s+del\s+sistema|las\s+instrucciones\s+base)\b",
        r"(?i)\bdo\s+anything\s+now\b",
        r"(?i)\bDAN\s+mode\b",
        r"(?i)\bsystem\s+override\b",
        r"(?i)\bjailbreak\b",
    ]

    MAX_PROMPT_LENGTH = 8000  # Caracteres máximos permitidos por prompt

    @classmethod
    def sanitize_prompt(cls, prompt: str) -> tuple[bool, str, dict[str, Any]]:
        """Valida y sanitiza el prompt del usuario.

        Devuelve:
            (is_safe: bool, sanitized_prompt: str, diagnostics: dict)
        """
        if not prompt or not isinstance(prompt, str):
            return False, "", {"status": "REJECTED", "reason": "Prompt vacío o formato inválido"}

        # 1. Verificación de longitud
        if len(prompt) > cls.MAX_PROMPT_LENGTH:
            return False, "", {
                "status": "REJECTED",
                "reason": f"Longitud excede el límite seguro ({len(prompt)} > {cls.MAX_PROMPT_LENGTH})",
            }

        # 2. Detección de Prompt Injections y Jailbreaks
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            match = re.search(pattern, prompt)
            if match:
                return False, "", {
                    "status": "BLOCKED_BY_GUARDRAIL",
                    "threat": "OWASP_LLM_01_PROMPT_INJECTION",
                    "matched_pattern": match.group(0),
                    "reason": "Intento de alteración de directivas o bypass de seguridad detectado.",
                }

        # 3. Sanitización de caracteres de control invisibles
        cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", prompt).strip()

        return True, cleaned, {"status": "PASSED", "length": len(cleaned)}
