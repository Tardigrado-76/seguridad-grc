from __future__ import annotations
import re
from typing import List, Dict, Any

class SecretDetector:
    """Scans payloads, logs, and configurations to prevent credential and secret leakages."""

    PATTERNS = {
        "AWS_KEY": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "GENERIC_SECRET": r"(?i)(?:api_key|apikey|secret|password|token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
        "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "JWT_TOKEN": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    }

    @classmethod
    def scan(cls, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for secret_type, pattern in cls.PATTERNS.items():
            for match in re.finditer(pattern, content):
                findings.append({
                    "secret_type": secret_type,
                    "span": match.span(),
                    "snippet": f"{content[max(0, match.start()-5):min(len(content), match.end()+5)]}"
                })
        return findings
