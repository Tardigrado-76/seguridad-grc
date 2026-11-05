"""Quantigrade GCR - OWASP AI Guardrails & Prompt Security Middleware.

Reuses and modernizes the battle-tested guardrails from NUEVO ORDEN (Rag_Regulado.py):
- OWASP LLM01: Prompt Injection / Jailbreak detection
- OWASP LLM02: Sensitive Information Disclosure (PII redaction: DNI, Credit Cards, Emails, API Keys)
- EU AI Act Art. 15 (Cybersecurity & Robustness) & DORA Art. 6 (ICT Risk Governance)
- Tamper-evident SHA-256 hash-chained audit logging
100% native Python without Docker.
"""

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

class OWASPAIGuardrails:
    """Enterprise AI Guardrails protection layer for compliance and security."""

    INJECTION_PATTERNS = [
        r"(ignore|ignora|bypass|override)\s+(the\s+)?(previous|prior|system|instructions|instrucciones|directivas)",
        r"(forget|olvida)\s+(everything|all|system|instructions|lo\s+anterior)",
        r"revela\s+(tus\s+)?(instrucciones|prompt|directivas|reglas)",
        r"reveal\s+(your\s+)?(instructions|prompt|rules|system)",
        r"(act\s+as|actua\s+como|eres\s+un|you\s+are\s+now|eres\s+ahora)\s+(administrator|admin|root|nuevo\s+modelo|jailbreak)",
        r"\bsudo\s+su\b",
        r"\bdelete\s+from\s+\w+\b",
        r"\bselect\s+\*\s+from\s+\w+\b",
        r"\bdrop\s+table\b",
        r"(muestra|revela|accede\s+a)\s+(la\s+)?(base\s+de\s+datos|db|database|tablas)",
    ]

    PII_PATTERNS = {
        "DNI / NIE (España)": r"\b(?:[0-9]{8}[A-Z]|[XYZ][0-9]{7}[A-Z])\b",
        "Tarjeta de Crédito": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b",
        "Correo Electrónico": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "Teléfono Móvil (España)": r"\b(?:(?:\+34|0034)?[ -]?)?[6789]\d{8}\b",
        "API Key (Simulada/Real)": r"\b(?:sk-[a-zA-Z0-9]{32,64}|AIzaSy[a-zA-Z0-9-_]{33}|ghp_[a-zA-Z0-9]{36})\b",
    }

    def __init__(self, max_audit_entries: int = 1000):
        self.max_audit_entries = max_audit_entries
        self.audit_log: List[Dict[str, Any]] = []
        self._last_hash = "0" * 64

    def scan_input(self, text: str) -> Dict[str, Any]:
        """Scans prompt or input text against OWASP LLM Top 10 vulnerabilities."""
        start_time = time.perf_counter()

        # 1. Check Prompt Injection (OWASP LLM01)
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                event = self.record_audit_event(
                    event_type="BLOCKED",
                    prompt=text,
                    is_blocked=True,
                    reason="Intento de Prompt Injection (Inyección de Directivas)",
                    owasp_tag="OWASP LLM01: Prompt Injection",
                    compliance_tags=["EU AI Act Artículo 15 (Ciberseguridad)", "DORA Artículo 6 (Control TIC)"],
                    latency_ms=latency_ms
                )
                return {
                    "is_blocked": True,
                    "reason": event["reason"],
                    "owasp": event["owasp_tag"],
                    "compliance": event["compliance_tags"],
                    "sanitized_text": "[INYECCIÓN BLOQUEADA]",
                    "latency_ms": round(latency_ms, 2)
                }

        # 2. Check PII & Sensitive Credentials (OWASP LLM02)
        detected_pii = []
        for pii_name, pattern in self.PII_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                detected_pii.append(f"{pii_name} ({len(matches)} hallazgos)")

        if detected_pii:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            sanitized = self.mask_pii(text)
            event = self.record_audit_event(
                event_type="BLOCKED_OR_REDACTED",
                prompt=text,
                is_blocked=True,
                reason="Fuga de Datos Sensibles (PII / Credenciales)",
                owasp_tag="OWASP LLM02: Sensitive Information Disclosure",
                compliance_tags=["RGPD Artículo 32 (Seguridad del Tratamiento)", "DORA Artículo 6"],
                latency_ms=latency_ms,
                details=f"Detectado: {', '.join(detected_pii)}"
            )
            return {
                "is_blocked": True,
                "reason": event["reason"],
                "owasp": event["owasp_tag"],
                "compliance": event["compliance_tags"],
                "sanitized_text": sanitized,
                "detected_pii": detected_pii,
                "latency_ms": round(latency_ms, 2)
            }

        # Safe input
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        self.record_audit_event(
            event_type="SAFE",
            prompt=text,
            is_blocked=False,
            reason="Safe",
            owasp_tag="None",
            compliance_tags=["EU AI Act Conforme"],
            latency_ms=latency_ms
        )
        return {
            "is_blocked": False,
            "reason": "Safe",
            "owasp": "None",
            "compliance": ["EU AI Act Conforme"],
            "sanitized_text": text,
            "latency_ms": round(latency_ms, 2)
        }

    def mask_pii(self, text: str) -> str:
        """Redacts sensitive PII from text replacing with anonymized tokens."""
        redacted = text
        redacted = re.sub(self.PII_PATTERNS["DNI / NIE (España)"], "[DNI_REDACTADO]", redacted)
        redacted = re.sub(self.PII_PATTERNS["Tarjeta de Crédito"], "[TARJETA_REDACTADA]", redacted)
        redacted = re.sub(self.PII_PATTERNS["Correo Electrónico"], "[EMAIL_REDACTADO]", redacted)
        redacted = re.sub(self.PII_PATTERNS["Teléfono Móvil (España)"], "[TELEFONO_REDACTADO]", redacted)
        redacted = re.sub(self.PII_PATTERNS["API Key (Simulada/Real)"], "[API_KEY_REDACTADA]", redacted)
        return redacted

    def record_audit_event(
        self,
        event_type: str,
        prompt: str,
        is_blocked: bool,
        reason: str,
        owasp_tag: str,
        compliance_tags: List[str],
        latency_ms: float,
        details: str = ""
    ) -> Dict[str, Any]:
        """Appends a cryptographic hash-chained audit event for immutable audit trail."""
        masked_prompt = self.mask_pii(prompt) if "OWASP LLM02" in owasp_tag else (
            f"[INYECCIÓN BLOQUEADA] {prompt[:40]}..." if is_blocked else prompt
        )

        event_payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "prompt": masked_prompt,
            "is_blocked": is_blocked,
            "reason": reason,
            "owasp_tag": owasp_tag,
            "compliance_tags": compliance_tags,
            "details": details,
            "latency_ms": round(latency_ms, 2),
            "prev_hash": self._last_hash
        }

        # Calculate chain hash
        serialized = json.dumps(event_payload, sort_keys=True)
        current_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        event_payload["event_hash"] = current_hash
        self._last_hash = current_hash

        self.audit_log.insert(0, event_payload)
        if len(self.audit_log) > self.max_audit_entries:
            self.audit_log.pop()

        return event_payload

    def verify_audit_log_integrity(self) -> Dict[str, Any]:
        """Verifies mathematical integrity of the SHA-256 hash chain in reverse order."""
        if not self.audit_log:
            return {"status": "EMPTY_LOG", "integrity_verified": True, "total_records": 0}

        # Re-verify from oldest to newest
        chronological = list(reversed(self.audit_log))
        expected_prev = "0" * 64

        for idx, entry in enumerate(chronological):
            if entry.get("prev_hash") != expected_prev:
                return {
                    "status": "TAMPERING_DETECTED",
                    "integrity_verified": False,
                    "broken_at_index": idx,
                    "record_timestamp": entry.get("timestamp")
                }
            
            # Recalculate hash without 'event_hash'
            copy_entry = dict(entry)
            stored_hash = copy_entry.pop("event_hash")
            recalculated = hashlib.sha256(json.dumps(copy_entry, sort_keys=True).encode("utf-8")).hexdigest()
            if stored_hash != recalculated:
                return {
                    "status": "HASH_MISMATCH",
                    "integrity_verified": False,
                    "broken_at_index": idx
                }
            expected_prev = stored_hash

        return {
            "status": "INTEGRITY_VERIFIED",
            "integrity_verified": True,
            "total_records": len(self.audit_log),
            "head_hash": self._last_hash
        }
