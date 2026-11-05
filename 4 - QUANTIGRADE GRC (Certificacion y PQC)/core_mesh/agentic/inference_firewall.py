"""
Inference Firewall & DLP Guardrails for LLM Agents in Quantigrade GCR.
Compliant with EU AI Act Art. 14/15, OWASP LLM 2025 (LLM01/LLM06), and RGPD Art. 32.
"""
import re
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


class FirewallVerdict(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


@dataclass
class InjectionInspectionResult:
    is_safe: bool
    reason: str = ""
    matched_pattern: str = ""


@dataclass
class SecretInspectionResult:
    has_secrets: bool
    detected_types: List[str] = field(default_factory=list)


@dataclass
class InferenceInspectionRecord:
    input_sha256: str
    output_sha256: str
    verdict: FirewallVerdict
    sanitized_content: str
    redactions_count: Dict[str, int] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)


class PromptInjectionShield:
    """Detects prompt injection, jailbreak attempts, and instruction overrides."""

    PATTERNS = [
        (r"ignore\s+(all\s+)?previous\s+instructions", "Jailbreak: ignore previous instructions override"),
        (r"reveal\s+(the\s+)?system\s+prompt", "Prompt Leaking: attempt to extract system prompt"),
        (r"you\s+are\s+now\s+(dan|unrestricted|godmode|jailbroken)", "Jailbreak: persona override"),
        (r"disregard\s+(the\s+)?(safety|rules|constraints)", "Jailbreak: safety constraint bypass"),
        (r"system\s+override\s+code\b", "Jailbreak: faux system command injection"),
    ]

    def inspect(self, text: str) -> InjectionInspectionResult:
        for pattern, reason in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return InjectionInspectionResult(is_safe=False, reason=reason, matched_pattern=pattern)
        return InjectionInspectionResult(is_safe=True)


class PiiSanitizer:
    """Sanitizes PII data (DNI/NIE, emails, IBANs, phone numbers) under RGPD Art. 32."""

    PATTERNS = {
        "dni": (r"\b[XYZ]?\d{7,8}[A-Z]\b", "REDACTED_DNI"),
        "email": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "REDACTED_EMAIL"),
        "iban": (r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", "REDACTED_IBAN"),
        "phone": (r"\b(?:\+34|0034)?[6789]\d{8}\b", "REDACTED_PHONE"),
    }

    def sanitize(self, text: str) -> Tuple[str, Dict[str, int]]:
        sanitized = text
        counts: Dict[str, int] = {}

        for pii_type, (regex, placeholder) in self.PATTERNS.items():
            matches = list(re.finditer(regex, sanitized))
            counts[pii_type] = len(matches)
            for m in reversed(matches):
                val = m.group(0)
                h = hashlib.sha256(val.encode("utf-8")).hexdigest()[:6]
                token = f"[{placeholder}_{h}]"
                sanitized = sanitized[:m.start()] + token + sanitized[m.end():]

        return sanitized, counts


class SecretDetector:
    """Detects leaked credentials, private keys, API tokens, and JWTs."""

    PATTERNS = {
        "AWS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
        "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "JWT": r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "BEARER_TOKEN": r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}",
        "GENERIC_SECRET": r"(?i)\b(?:api[_-]?key|secret|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    }

    def inspect(self, text: str) -> SecretInspectionResult:
        detected = []
        for sec_type, regex in self.PATTERNS.items():
            if re.search(regex, text):
                detected.append(sec_type)
        return SecretInspectionResult(has_secrets=len(detected) > 0, detected_types=detected)


class InferenceFirewall:
    """
    Main inference firewall orchestrator for Quantigrade GCR agents.
    Provides fail-closed protection and audit logging for EU AI Act compliance.
    """

    def __init__(self):
        self.injection_shield = PromptInjectionShield()
        self.pii_sanitizer = PiiSanitizer()
        self.secret_detector = SecretDetector()

    def process_input(self, prompt: str) -> InferenceInspectionRecord:
        input_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        reasons = []

        # 1. Prompt Injection Check
        injection = self.injection_shield.inspect(prompt)
        if not injection.is_safe:
            reasons.append(injection.reason)
            return InferenceInspectionRecord(
                input_sha256=input_hash,
                output_sha256="",
                verdict=FirewallVerdict.BLOCK,
                sanitized_content="[BLOCKED_PROMPT_INJECTION]",
                reasons=reasons,
            )

        # 2. Secret Detection
        secret_res = self.secret_detector.inspect(prompt)
        sanitized = prompt
        if secret_res.has_secrets:
            reasons.append(f"Secrets detected: {', '.join(secret_res.detected_types)}")
            for sec_type, regex in self.secret_detector.PATTERNS.items():
                sanitized = re.sub(regex, f"[REDACTED_{sec_type}]", sanitized)

        # 3. PII Sanitization
        sanitized, pii_counts = self.pii_sanitizer.sanitize(sanitized)
        total_pii = sum(pii_counts.values())

        if total_pii > 0:
            reasons.append(f"PII redacted: {pii_counts}")

        verdict = FirewallVerdict.ALLOW
        if secret_res.has_secrets or total_pii > 0:
            verdict = FirewallVerdict.SANITIZE

        output_hash = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()

        return InferenceInspectionRecord(
            input_sha256=input_hash,
            output_sha256=output_hash,
            verdict=verdict,
            sanitized_content=sanitized,
            redactions_count=pii_counts,
            reasons=reasons,
        )

    def process_output(self, response: str) -> InferenceInspectionRecord:
        """Inspects model outputs to prevent data leakage and secret exfiltration."""
        return self.process_input(response)
