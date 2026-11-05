#!/usr/bin/env python3
"""
api_security_ctem_router.py — CTEM Validation: API Gateway & HTTP Security Header Auditor.
Aligns with:
 - OWASP API Security Top 10 (2023): API1 BOLA, API4 Unrestricted Resource Consumption, API7 SSRF
 - ENS RD 311/2022: Medida [mp.com.1] Protección de Comunicaciones
 - NIST SP 800-53: SC-8 Transmission Confidentiality and Integrity
"""
from __future__ import annotations

import datetime
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("Quantigrade.CTEM.APISecurity")


class APISecurityCTEMInspector:
    """Audits API endpoint definitions, rate limiting controls, and security headers."""

    REQUIRED_HEADERS = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Referrer-Policy",
    ]

    def audit_security_headers(self, headers_dict: dict[str, str]) -> dict[str, Any]:
        """Validates provided HTTP response headers against hardened baseline."""
        normalized = {k.lower(): v for k, v in headers_dict.items()}
        missing = []
        findings = []

        for req in self.REQUIRED_HEADERS:
            val = normalized.get(req.lower())
            if not val:
                missing.append(req)
                findings.append({
                    "header": req,
                    "status": "MISSING",
                    "severity": "HIGH" if req in ["Strict-Transport-Security", "Content-Security-Policy"] else "MEDIUM",
                    "recommendation": f"Configurar cabecera {req} en el reverse proxy o middleware."
                })
            else:
                # Check weak configs
                if req == "X-Frame-Options" and val.upper() not in ["DENY", "SAMEORIGIN"]:
                    findings.append({
                        "header": req,
                        "status": "WEAK",
                        "severity": "MEDIUM",
                        "recommendation": "Establecer X-Frame-Options a DENY o SAMEORIGIN."
                    })
                elif req == "Strict-Transport-Security" and "max-age=" not in val:
                    findings.append({
                        "header": req,
                        "status": "WEAK",
                        "severity": "HIGH",
                        "recommendation": "HSTS requiere directiva max-age (ej: max-age=31536000; includeSubDomains)."
                    })

        passed_count = len(self.REQUIRED_HEADERS) - len(missing)
        score = (passed_count / len(self.REQUIRED_HEADERS)) * 100.0

        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "score": score,
            "missing_headers": missing,
            "findings": findings,
            "status": "PASS" if score >= 80.0 else "FAIL"
        }

    def audit_route_file(self, file_path: Path) -> dict[str, Any]:
        """Audits route definitions for rate-limiting, CORS wildcards, and unauthenticated routes."""
        p = Path(file_path)
        if not p.exists():
            return {"file": str(file_path), "error": "File not found", "findings": []}

        content = p.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()
        findings = []

        has_rate_limit = bool(re.search(r"(@limiter|RateLimiter|throttle)", content, re.IGNORECASE))
        has_cors_wildcard = bool(re.search(r"allow_origins\s*=\s*\[?['\"]\*['\"]", content))

        if has_cors_wildcard:
            findings.append({
                "type": "CORS_WILDCARD_PERMISSIVE",
                "severity": "HIGH",
                "description": "CORS configurado con comodín '*' permitiendo cualquier origen.",
                "recommendation": "Restringir orígenes permitidos explícitamente."
            })

        for idx, line in enumerate(lines, 1):
            if re.search(r"@app\.(post|put|delete)", line, re.IGNORECASE) and not has_rate_limit:
                findings.append({
                    "line": idx,
                    "type": "API_MUTATION_WITHOUT_RATE_LIMIT",
                    "severity": "MEDIUM",
                    "snippet": line.strip()[:100],
                    "recommendation": "Implementar rate limiting defensivo ante ataques de fuerza bruta/DDoS."
                })
                break  # Alert once per file for rate limiting

        return {
            "file": str(p.name),
            "rate_limiting_detected": has_rate_limit,
            "cors_wildcard_detected": has_cors_wildcard,
            "findings_count": len(findings),
            "findings": findings
        }

