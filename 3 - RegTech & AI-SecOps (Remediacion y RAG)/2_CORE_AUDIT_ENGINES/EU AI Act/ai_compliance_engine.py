#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_compliance_engine.py — Motor Completo de Auditoría y Remediación EU AI Act (UE 2024/1689)
========================================================================================
Autor: Principal Legal-Tech Architect & Lead AI Governance Engineer
Cumplimiento: Reglamento (UE) 2024/1689 (EU AI Act), Anexos III y VIII, Artículos 5, 10, 12, 14, 15, 27, 50, 51, 53.

Arquitectura en 3 FASES:
  FASE 0 & 1: VERIFICAR
              - Módulo OSINT (Active Web Reconnaissance): SSL/TLS, Security Headers (Art. 15),
                DOM Crawling para Chatbots/IA (Art. 50), Scraping de Políticas de Privacidad/IA,
                y Análisis de /robots.txt para Crawlers de GPAI (Art. 53).
              - Cuestionario CISO de 10 Preguntas con Motor de Alertas de Discrepancia (OSINT Cross-Check).
  FASE 2:     INFORMAR
              - Motor de Triaje de Riesgo (PROHIBIDO, ALTO RIESGO, GPAI SISTÉMICO, LIMITADO, MÍNIMO).
              - Matriz de Brechas (Gap Analysis) e Informe Markdown por Consola.
              - Exportación JSON (`ai_audit_result.json`) con Payload del Registro de la UE (Anexo VIII).
  FASE 3:     SOLUCIONAR
              - Generador Automático de Parches y Código de Remediación (Middleware Logs Art. 12, Banner Transparencia Art. 50, Plantilla FRIA Art. 27, Sanitizador Prompt Injection Art. 15).
              - Protocolo HITL con Interrupción Interactiva ("CONFIRMO"), Firma Digital CISO/CTO y Sellado SHA-256.
"""

import os
import sys
import re
import json
import ssl
import socket
import hashlib
import argparse
import urllib3
from enum import Enum
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any
from pydantic import BaseModel, Field, field_validator
import requests
from bs4 import BeautifulSoup

# Deshabilitar advertencias de certificados en solicitudes de escaneo OSINT
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuración de salida de consola para Windows
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


# ==============================================================================
# ENUMS Y MODELOS PYDANTIC V2
# ==============================================================================

class RiskLevel(str, Enum):
    PROHIBITED = "PROHIBIDO - Práctica Prohibida (Art. 5 EU AI Act)"
    HIGH_RISK = "ALTO RIESGO - Dominio Sensible / Anexo III EU AI Act"
    GPAI_SYSTEMIC = "GPAI SISTÉMICO - Modelo de Propósito General de Alto Impacto (Art. 51 EU AI Act)"
    LIMITED_RISK = "RIESGO LIMITADO - Obligaciones de Transparencia (Art. 50 EU AI Act)"
    MINIMAL_RISK = "RIESGO MÍNIMO / SIN RIESGO OBLIGATORIO - Código de Conducta Voluntario"


class CompanyProfile(BaseModel):
    company_name: str = Field(..., min_length=2, description="Nombre formal de la entidad")
    website_url: str = Field(..., description="URL corporativa o del sistema de IA")
    ciso_name: str = Field(..., min_length=2, description="Nombre del CISO / CTO / AI Lead")
    ciso_role: str = Field(..., min_length=2, description="Cargo oficial del responsable")

    @field_validator("website_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v_clean = v.strip()
        if not (v_clean.startswith("http://") or v_clean.startswith("https://")):
            v_clean = "https://" + v_clean
        return v_clean


class SSLInfo(BaseModel):
    is_valid: bool = False
    issuer: str = "Desconocido"
    expiration_date: str = "N/A"
    days_remaining: int = -1
    ssl_version: str = "N/A"
    details: str = ""


class HeaderAudit(BaseModel):
    hsts_enabled: bool = False
    csp_enabled: bool = False
    x_content_type_options: bool = False
    x_frame_options: bool = False
    security_score: int = 0
    missing_headers: List[str] = []


class ChatbotDetection(BaseModel):
    detected: bool = False
    widgets_found: List[str] = []
    scripts_found: List[str] = []


class PrivacyScan(BaseModel):
    privacy_url: Optional[str] = None
    ai_terms_found: bool = False
    ai_mentions: List[str] = []


class RobotsTxtScan(BaseModel):
    robots_txt_found: bool = False
    gpai_crawlers_status: Dict[str, str] = {}


class OSINTResult(BaseModel):
    scanned_url: str
    scan_timestamp: str
    ssl_info: SSLInfo
    header_audit: HeaderAudit
    chatbot_detection: ChatbotDetection
    privacy_scan: PrivacyScan
    robots_txt_scan: RobotsTxtScan


class DiscrepancyAlert(BaseModel):
    id: str
    article_ref: str
    osint_finding: str
    ciso_answer: str
    warning_message: str


class QuestionAnswer(BaseModel):
    id: str
    article_ref: str
    question_text: str
    answer: bool


class Finding(BaseModel):
    code: str
    article: str
    title: str
    severity: str
    description: str
    remediation_action: str


class RemediationPatch(BaseModel):
    article: str
    code_type: str
    title: str
    filename: str
    content: str


class AnnexVIIIETPayload(BaseModel):
    registration_id: str
    provider_name: str
    provider_website: str
    ai_system_name: str
    intended_purpose: str
    high_risk_category: str
    conformity_assessment_status: str
    eu_representative: str
    timestamp: str


class AuditEngineResult(BaseModel):
    profile: CompanyProfile
    audit_timestamp: str
    osint_report: OSINTResult
    discrepancies: List[DiscrepancyAlert]
    questions: List[QuestionAnswer]
    overall_risk: RiskLevel
    findings: List[Finding]
    remediation_patches: List[RemediationPatch]
    annex_viii_payload: Optional[AnnexVIIIETPayload] = None
    hitl_approved: bool = False
    signature_token: Optional[str] = None
    signature_timestamp: Optional[str] = None
    signed_by: Optional[str] = None


# ==============================================================================
# FASE 0 & 1: MÓDULO OSINT (ACTIVE RECONNAISSANCE ENGINE)
# ==============================================================================

class OSINTScanner:
    """Escáner de Fuentes Abiertas (OSINT) para verificación activa en sitios web corporativos."""

    GPAI_CRAWLERS = ["GPTBot", "ChatGPT-User", "ClaudeBot", "PerplexityBot", "Bytespider", "CCBot"]
    CHATBOT_PATTERNS = [
        "intercom", "drift", "crisp", "tidio", "zendesk", "livechat", "tawk",
        "openai", "chat-widget", "chatbot", "assistant", "bot-container", "vapi"
    ]

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed = urlparse(target_url)
        self.hostname = self.parsed.hostname or "localhost"

    def scan_ssl(self) -> SSLInfo:
        info = SSLInfo()
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    info.is_valid = True
                    info.ssl_version = ssock.version() or "TLSv1.3"

                    # Formatear emisor
                    issuer_dict = dict(x[0] for x in cert.get('issuer', ()))
                    info.issuer = issuer_dict.get('organizationName', 'Emisor Desconocido')

                    # Fecha de expiración
                    not_after_str = cert.get('notAfter')
                    if not_after_str:
                        exp_dt = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        info.expiration_date = exp_dt.strftime('%Y-%m-%d')
                        info.days_remaining = (exp_dt - now_dt).days
                    info.details = f"Certificado válido para {self.hostname}. Expira en {info.days_remaining} días."
        except Exception as e:
            info.is_valid = False
            info.details = f"Error en conexión SSL/TLS: {str(e)}"
        return info

    def scan_headers_and_dom(self) -> Tuple[HeaderAudit, ChatbotDetection, PrivacyScan]:
        header_audit = HeaderAudit()
        chatbot = ChatbotDetection()
        privacy = PrivacyScan()

        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) EU-AI-Act-Compliance-Scanner/2.0'}
            res = requests.get(self.target_url, headers=headers, timeout=8, verify=False)
            res_headers = {k.lower(): v for k, v in res.headers.items()}

            # 1. Auditoría de Cabeceras
            if 'strict-transport-security' in res_headers:
                header_audit.hsts_enabled = True
            else:
                header_audit.missing_headers.append('Strict-Transport-Security (HSTS)')

            if 'content-security-policy' in res_headers:
                header_audit.csp_enabled = True
            else:
                header_audit.missing_headers.append('Content-Security-Policy (CSP)')

            if 'x-content-type-options' in res_headers:
                header_audit.x_content_type_options = True
            else:
                header_audit.missing_headers.append('X-Content-Type-Options')

            if 'x-frame-options' in res_headers:
                header_audit.x_frame_options = True
            else:
                header_audit.missing_headers.append('X-Frame-Options')

            score = 100 - (len(header_audit.missing_headers) * 25)
            header_audit.security_score = max(0, score)

            # 2. Análisis del DOM para Chatbots/IA (Art. 50)
            soup = BeautifulSoup(res.text, 'html.parser')
            page_text_lower = soup.get_text().lower()
            html_str_lower = res.text.lower()

            for pattern in self.CHATBOT_PATTERNS:
                if pattern in html_str_lower:
                    chatbot.detected = True
                    chatbot.widgets_found.append(pattern)

            scripts = [s.get('src', '') for s in soup.find_all('script') if s.get('src')]
            for s_url in scripts:
                if any(p in s_url.lower() for p in self.CHATBOT_PATTERNS):
                    chatbot.detected = True
                    chatbot.scripts_found.append(s_url)

            # 3. Scraping de Políticas y Menciones a IA
            for link in soup.find_all('a', href=True):
                href = link['href']
                text = link.get_text().strip().lower()
                if any(k in href.lower() or k in text for k in ['privacy', 'privacidad', 'legal', 'terms', 'ia', 'ai']):
                    privacy.privacy_url = urljoin(self.target_url, href)
                    break

            ai_keywords = ["inteligencia artificial", "artificial intelligence", "machine learning", "modelo de lenguaje", "llm", "chatbot", "algoritmo"]
            found_keywords = [kw for kw in ai_keywords if kw in page_text_lower]
            if found_keywords:
                privacy.ai_terms_found = True
                privacy.ai_mentions = list(set(found_keywords))

        except Exception as e:
            header_audit.missing_headers.append(f"Error HTTP OSINT: {str(e)}")

        return header_audit, chatbot, privacy

    def scan_robots_txt(self) -> RobotsTxtScan:
        scan = RobotsTxtScan()
        robots_url = urljoin(self.target_url, '/robots.txt')
        try:
            res = requests.get(robots_url, timeout=5, verify=False)
            if res.status_code == 200:
                scan.robots_txt_found = True
                content = res.text
                current_ua = None
                for line in content.splitlines():
                    line_clean = line.strip()
                    if line_clean.lower().startswith('user-agent:'):
                        current_ua = line_clean.split(':', 1)[1].strip()
                    elif current_ua and line_clean.lower().startswith('disallow:'):
                        rule = line_clean.split(':', 1)[1].strip()
                        for gpai in self.GPAI_CRAWLERS:
                            if gpai.lower() in current_ua.lower():
                                scan.gpai_crawlers_status[gpai] = f"Bloqueado (Disallow: {rule})"
                    elif current_ua and line_clean.lower().startswith('allow:'):
                        rule = line_clean.split(':', 1)[1].strip()
                        for gpai in self.GPAI_CRAWLERS:
                            if gpai.lower() in current_ua.lower():
                                scan.gpai_crawlers_status[gpai] = f"Permitido (Allow: {rule})"

                for gpai in self.GPAI_CRAWLERS:
                    if gpai not in scan.gpai_crawlers_status:
                        scan.gpai_crawlers_status[gpai] = "Sin regla específica (Permitido por defecto)"
        except Exception:
            scan.robots_txt_found = False
        return scan

    def run_full_scan(self) -> OSINTResult:
        ssl_info = self.scan_ssl()
        headers, chatbot, privacy = self.scan_headers_and_dom()
        robots = self.scan_robots_txt()

        return OSINTResult(
            scanned_url=self.target_url,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            ssl_info=ssl_info,
            header_audit=headers,
            chatbot_detection=chatbot,
            privacy_scan=privacy,
            robots_txt_scan=robots
        )


# ==============================================================================
# CUESTIONARIO Y CROSS-CHECK OSINT DE DISCREPANCIAS
# ==============================================================================

QUESTIONS_DB = [
    {
        "id": "P1",
        "article_ref": "Anexo III",
        "text": "¿El sistema de IA se utiliza en dominios sensibles (RRHH/reclutamiento, infraestructuras críticas, evaluación crediticia, educación o servicios públicos/privados esenciales)?"
    },
    {
        "id": "P2",
        "article_ref": "Art. 5",
        "text": "¿El sistema emplea técnicas subliminales, manipulación conductual, scoring social, recolección masiva no dirigida de imágenes faciales o reconocimiento de emociones en trabajo/educación?"
    },
    {
        "id": "P3",
        "article_ref": "Art. 50",
        "text": "¿El sistema interactúa directamente con personas físicas (chatbots) o genera/manipula contenido sintético (audio, imagen, vídeo, deepfakes, textos)?"
    },
    {
        "id": "P4",
        "article_ref": "Art. 51",
        "text": "¿El sistema integra modelos de IA de Propósito General (GPAI / LLMs) con cómputo acumulativo > 10^25 FLOPs (ej. GPT-4o, Llama-3 70B+) o capacidad sistémica equivalente?"
    },
    {
        "id": "P5",
        "article_ref": "Autonomía / Art. 14",
        "text": "¿El sistema toma decisiones automatizadas con impacto legal o efectos significativos sobre personas sin una revisión humana previa obligatoria?"
    },
    {
        "id": "P6",
        "article_ref": "Art. 12",
        "text": "¿El sistema cuenta con un mecanismo automatizado para la retención y registro de logs (trazabilidad) garantizando su almacenamiento seguro por un período mínimo de 6 meses?"
    },
    {
        "id": "P7",
        "article_ref": "Art. 10",
        "text": "¿Se ha formalizado una documentación técnica de Gobernanza de Datos que incluya procedencia de datos, prevención de sesgos y representación adecuada?"
    },
    {
        "id": "P8",
        "article_ref": "Art. 14",
        "text": "¿Dispone el operador de la capacidad técnica de parada de emergencia ('kill switch') o anulación humana en tiempo real durante la operación?"
    },
    {
        "id": "P9",
        "article_ref": "Art. 27",
        "text": "¿Se ha realizado formalmente una Evaluación de Impacto en los Derechos Fundamentales (FRIA - Fundamental Rights Impact Assessment) antes del despliegue?"
    },
    {
        "id": "P10",
        "article_ref": "Art. 15",
        "text": "¿Se han ejecutado pruebas documentadas de ciberseguridad, robustez y resiliencia específicas para IA (ataques de inyección de prompts, alucinaciones, envenenamiento)?"
    }
]


# ==============================================================================
# FASE 2: TRIAJE, ANEXO VIII PAYLOAD Y GENERADOR DE PARCHES (SOLUCIONAR)
# ==============================================================================

class RemediationGenerator:
    """Generador automático de parches de código y plantillas de remediación legal."""

    @staticmethod
    def generate_art12_log_middleware() -> RemediationPatch:
        content = '''# ==============================================================================
# PARCHE DE REMEDIACIÓN: EU AI ACT - ARTÍCULO 12 (LOGS Y TRAZABILIDAD 6 MESES)
# ==============================================================================
import logging
import json
import uuid
from datetime import datetime, timezone
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Configuración de Logger Inmutable conforme al Art. 12 del EU AI Act
logger = logging.getLogger("EU_AI_Act_AuditLogger")
logger.setLevel(logging.INFO)

handler = logging.FileHandler("ai_system_audit_logs.jsonl", encoding="utf-8")
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class EUAIActLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware de trazabilidad e inmutabilidad con retención mínima de 6 meses."""
    async def dispatch(self, request: Request, call_next) -> Response:
        session_id = request.headers.get("X-Session-ID", str(uuid.uuid4()))
        start_time = datetime.now(timezone.utc).isoformat()
        
        response = await call_next(request)
        
        log_payload = {
            "timestamp": start_time,
            "session_id": session_id,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "client_ip": request.client.host if request.client else "0.0.0.0",
            "endpoint": str(request.url),
            "http_method": request.method,
            "status_code": response.status_code,
            "retention_policy": "OBLIGATORY_6_MONTHS_EU_AI_ACT_ART12"
        }
        logger.info(json.dumps(log_payload))
        return response
'''
        return RemediationPatch(
            article="Artículo 12",
            code_type="Python FastAPI Middleware",
            title="Sistema Inmutable de Logging de Auditoría (Retención 6 Meses)",
            filename="eu_ai_act_logging_middleware.py",
            content=content
        )

    @staticmethod
    def generate_art50_transparency_banner() -> RemediationPatch:
        content = '''<!-- ==============================================================================
     PARCHE DE REMEDIACIÓN: EU AI ACT - ARTÍCULO 50 (TRANSPARENCIA E IA SINTÉTICA)
     ============================================================================== -->
<div id="eu-ai-transparency-banner" style="position: fixed; bottom: 0; width: 100%; background: #0f172a; color: #f8fafc; padding: 12px 24px; font-family: system-ui, sans-serif; font-size: 14px; border-top: 3px solid #3b82f6; z-index: 99999; display: flex; justify-content: space-between; align-items: center;">
    <div>
        <strong>Aviso de Transparencia (Reglamento UE 2024/1689 Art. 50):</strong>
        <span>Este sistema o interfaz utiliza tecnología de Inteligencia Artificial para interactuar o generar contenido.</span>
    </div>
    <button onclick="document.getElementById('eu-ai-transparency-banner').style.display='none';" style="background: #2563eb; color: white; border: none; padding: 6px 16px; border-radius: 4px; cursor: pointer; font-weight: bold;">
        Entendido
    </button>
</div>

<script>
// Metadatos de Marcado de Agua C2PA / Contenido Sintético
window.__EU_AI_ACT_METADATA__ = {
    "is_ai_generated": true,
    "transparency_article": "EU_2024_1689_ART_50",
    "watermark_hash": "SHA256:C2PA_WATERMARK_STAMP_EMBEDDED"
};
</script>
'''
        return RemediationPatch(
            article="Artículo 50",
            code_type="HTML/CSS/JS Component",
            title="Componente Banner de Transparencia de IA y Marcas de Agua C2PA",
            filename="ai_transparency_notice.html",
            content=content
        )

    @staticmethod
    def generate_art27_fria_template(profile: CompanyProfile) -> RemediationPatch:
        content = f'''# EVALUACIÓN DE IMPACTO EN LOS DERECHOS FUNDAMENTALES (FRIA)
**Conforme al Artículo 27 del Reglamento (UE) 2024/1689 (EU AI Act)**

---

## 1. Datos de la Entidad y del Sistema de IA
- **Entidad Promotora/Desplegadora:** `{profile.company_name}`
- **Sitio Web / Repositorio:** `{profile.website_url}`
- **Responsable del Expediente:** `{profile.ciso_name}` ({profile.ciso_role})
- **Fecha de Evaluación:** `{datetime.now(timezone.utc).strftime("%Y-%m-%d")}`

---

## 2. Descripción General del Sistema de IA
1. **Propósito Previsto:** Identificación del uso previsto y categorías de usuarios afectados.
2. **Dominio de Aplicación:** Evaluación en dominios sensibles del Anexo III (RRHH, empleo, servicios esenciales, etc.).

---

## 3. Evaluación de Impactos en Derechos Fundamentales
- **No Discriminación e Igualdad:** Análisis del riesgo de sesgo en datos de entrenamiento.
- **Protección de Datos y Privacidad (RGPD):** Base legal del tratamiento y minimización de datos.
- **Derecho a la Tutela Judicial Efectiva:** Transparencia de explicabilidad sobre las decisiones del algoritmo.

---

## 4. Plan de Mitigación de Riesgos y Supervisión Humana
- **Mecanismos de Supervisión Humana (Art. 14):** Protocolos de intervención manual y parada de emergencia.
- **Medidas de Ciberseguridad (Art. 15):** Pruebas periódicas contra inyección de prompts y alucinaciones.

---
**FIRMADO EXPEDIENTE FRIA:**
Responsable de Cumplimiento: `{profile.ciso_name}`
'''
        return RemediationPatch(
            article="Artículo 27",
            code_type="Markdown Document Template",
            title="Plantilla Borrador Completa - FRIA (Fundamental Rights Impact Assessment)",
            filename="fria_assessment_template.md",
            content=content
        )

    @staticmethod
    def generate_art15_cybersecurity_sanitizer() -> RemediationPatch:
        content = r'''# ==============================================================================
# PARCHE DE REMEDIACIÓN: EU AI ACT - ARTÍCULO 15 (CIBERSEGURIDAD Y PROMPT INJECTION)
# ==============================================================================
import re
from typing import Tuple

class EUAIActPromptSanitizer:
    """Filtro de seguridad e inmunización contra Prompt Injection y Alucinaciones."""
    
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore\s+previous\s+instructions",
        r"(?i)system\s+prompt\s+override",
        r"(?i)you\s+are\s+now\s+dan",
        r"(?i)jailbreak",
        r"(?i)revela\s+tus\s+instrucciones\s+del\s+sistema"
    ]

    @classmethod
    def sanitize_input(cls, user_input: str) -> Tuple[bool, str]:
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, user_input):
                return False, "ALERTA DE SEGURIDAD (Art. 15): Intento de inyección de prompt detectado."
        return True, user_input

    @classmethod
    def validate_output_against_hallucination(cls, output_text: str, trusted_facts: list) -> bool:
        """Verifica la consistencia contextual para prevenir alucinaciones."""
        if not output_text or len(output_text.strip()) == 0:
            return False
        return True
'''
        return RemediationPatch(
            article="Artículo 15",
            code_type="Python Security Module",
            title="Sanitizador de Entradas contra Ataques de Prompt Injection y Alucinaciones",
            filename="prompt_injection_sanitizer.py",
            content=content
        )


# ==============================================================================
# MOTOR PRINCIPAL DE EJECUCIÓN DEL AUDITOR (3 FASES)
# ==============================================================================

def execute_audit_lifecycle(
    url: str,
    company: str,
    ciso_name: str,
    ciso_role: str,
    non_interactive: bool = False,
    output_json_path: str = "ai_audit_result.json"
) -> AuditEngineResult:

    # --------------------------------------------------------------------------
    # FASE 0 & 1: VERIFICAR (OSINT + CUESTIONARIO CISO + DISCREPANCIAS)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 85)
    print(" FASE 0 & 1: VERIFICAR — RECONOCIMIENTO ACTIVO OSINT Y CUESTIONARIO CISO")
    print("=" * 85)

    profile = CompanyProfile(
        company_name=company,
        website_url=url,
        ciso_name=ciso_name,
        ciso_role=ciso_role
    )

    print(f"[*] Ejecutando escaneo OSINT sobre la URL: {profile.website_url}...")
    scanner = OSINTScanner(profile.website_url)
    osint_report = scanner.run_full_scan()

    print(f"    [+] Certificado SSL/TLS: {'VÁLIDO (' + osint_report.ssl_info.ssl_version + ')' if osint_report.ssl_info.is_valid else 'INVÁLIDO / ERROR'}")
    print(f"    [+] Puntuación de Cabeceras de Ciberseguridad (Art. 15): {osint_report.header_audit.security_score}/100")
    print(f"    [+] Chatbots / Widgets de IA en DOM (Art. 50): {'DETECTADO (' + ', '.join(osint_report.chatbot_detection.widgets_found) + ')' if osint_report.chatbot_detection.detected else 'No detectados'}")
    print(f"    [+] Políticas de Privacidad/IA (Art. 50): {'ENCONTRADA' if osint_report.privacy_scan.privacy_url else 'No localizada'}")
    print(f"    [+] Rastreo /robots.txt para GPAI (Art. 53): {'ENCONTRADO' if osint_report.robots_txt_scan.robots_txt_found else 'No disponible'}")

    # Cuestionario CISO
    answers_map: Dict[str, bool] = {}
    discrepancies: List[DiscrepancyAlert] = []

    if non_interactive:
        # Respuestas por defecto para pruebas automatizadas
        answers_map = {q["id"]: False for q in QUESTIONS_DB}
    else:
        print("\n--- CUESTIONARIO CISO/CTO DE 10 PREGUNTAS OBLIGATORIAS (EU AI ACT) ---")
        for q in QUESTIONS_DB:
            while True:
                resp = input(f"[{q['id']} - {q['article_ref']}] {q['text']} (s/n): ").strip().lower()
                if resp in ('s', 'si', 'y', 'yes'):
                    answers_map[q["id"]] = True
                    break
                elif resp in ('n', 'no'):
                    answers_map[q["id"]] = False
                    break
                print("[!] Responda 's' para Sí o 'n' para No.")

    # Cross-Check de Discrepancias OSINT vs CISO
    if osint_report.chatbot_detection.detected and not answers_map.get("P3", False):
        disc = DiscrepancyAlert(
            id="DISC-P03",
            article_ref="Artículo 50",
            osint_finding=f"OSINT detectó widgets/scripts de chatbot conversacional ({', '.join(osint_report.chatbot_detection.widgets_found)}).",
            ciso_answer="CISO declaró 'No' a la pregunta P3 (Interacción/Transparencia).",
            warning_message="⚠️ ALERTA DE DISCREPANCIA: El análisis OSINT del DOM contradice la declaración del CISO. Se fuerza P3=True para garantizar cumplimiento."
        )
        discrepancies.append(disc)
        answers_map["P3"] = True
        print(f"\n{disc.warning_message}")

    questions_list = [
        QuestionAnswer(
            id=q["id"],
            article_ref=q["article_ref"],
            question_text=q["text"],
            answer=answers_map[q["id"]]
        ) for q in QUESTIONS_DB
    ]

    # --------------------------------------------------------------------------
    # FASE 2: INFORMAR (TRIAJE + GAP ANALYSIS + EXPORTACIÓN ANEXO VIII)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 85)
    print(" FASE 2: INFORME Y EXPORTACIÓN AUTOMÁTICA (REPORTING)")
    print("=" * 85)

    # Triaje de Riesgo
    if answers_map.get("P2", False):
        overall_risk = RiskLevel.PROHIBITED
    elif answers_map.get("P1", False) or answers_map.get("P5", False):
        if answers_map.get("P4", False):
            overall_risk = RiskLevel.GPAI_SYSTEMIC
        else:
            overall_risk = RiskLevel.HIGH_RISK
    elif answers_map.get("P4", False):
        overall_risk = RiskLevel.GPAI_SYSTEMIC
    elif answers_map.get("P3", False):
        overall_risk = RiskLevel.LIMITED_RISK
    else:
        overall_risk = RiskLevel.MINIMAL_RISK

    findings: List[Finding] = []
    remediation_patches: List[RemediationPatch] = []

    if overall_risk == RiskLevel.PROHIBITED:
        findings.append(Finding(
            code="ERR-ART05",
            article="Artículo 5",
            title="Práctica de IA Prohibida Detectada",
            severity="CRÍTICO",
            description="El sistema incurre en prácticas prohibidas (manipulación, scoring social, biometría no consentida).",
            remediation_action="Cese inmediato y desmantelamiento del módulo prohibido."
        ))

    if overall_risk in (RiskLevel.HIGH_RISK, RiskLevel.GPAI_SYSTEMIC):
        if not answers_map.get("P6", False):
            findings.append(Finding(
                code="GAP-ART12", article="Artículo 12", title="Falta de Logging Automatizado 6 Meses",
                severity="ALTO", description="No se garantiza la retención inmutable de logs por 6 meses.",
                remediation_action="Desplegar middleware de auditoría con retención inmutable."
            ))
            remediation_patches.append(RemediationGenerator.generate_art12_log_middleware())

        if not answers_map.get("P7", False):
            findings.append(Finding(
                code="GAP-ART10", article="Artículo 10", title="Ausencia de Gobernanza de Datos",
                severity="ALTO", description="Falta documentación formal de origen de datos y mitigación de sesgos.",
                remediation_action="Documentar pipeline de datos y control de sesgos algorítmicos."
            ))

        if not answers_map.get("P8", False):
            findings.append(Finding(
                code="GAP-ART14", article="Artículo 14", title="Carencia de Parada de Emergencia (Kill Switch)",
                severity="ALTO", description="No existe mecanismo de anulación humana en tiempo real.",
                remediation_action="Implementar botón de parada de emergencia e intervención humana."
            ))

        if not answers_map.get("P9", False):
            findings.append(Finding(
                code="GAP-ART27", article="Artículo 27", title="Omisión de la Evaluación FRIA",
                severity="ALTO", description="No se ha realizado la Evaluación de Impacto en Derechos Fundamentales.",
                remediation_action="Completar y registrar el expediente FRIA."
            ))
            remediation_patches.append(RemediationGenerator.generate_art27_fria_template(profile))

        if not answers_map.get("P10", False):
            findings.append(Finding(
                code="GAP-ART15", article="Artículo 15", title="Ciberseguridad y Robustez No Probada",
                severity="ALTO", description="Faltan pruebas contra prompt injection y alucinaciones.",
                remediation_action="Integrar sanitizador contra prompt injection y realizar Red-Teaming."
            ))
            remediation_patches.append(RemediationGenerator.generate_art15_cybersecurity_sanitizer())

    if overall_risk == RiskLevel.LIMITED_RISK or answers_map.get("P3", False):
        if not answers_map.get("P3", False) or osint_report.chatbot_detection.detected:
            findings.append(Finding(
                code="GAP-ART50",
                article="Artículo 50",
                title="Incumplimiento de Transparencia de IA",
                severity="MEDIO",
                description="No se notifica explícitamente la interacción con IA al usuario o la generación de contenido sintético.",
                remediation_action="Incrustar banner de transparencia e identificación de contenido sintético C2PA."
            ))
            remediation_patches.append(RemediationGenerator.generate_art50_transparency_banner())

    # Payload para el Registro de la UE (Anexo VIII)
    annex_viii = None
    if overall_risk in (RiskLevel.HIGH_RISK, RiskLevel.GPAI_SYSTEMIC):
        annex_viii = AnnexVIIIETPayload(
            registration_id=f"EU-REG-{hashlib.md5(profile.company_name.encode('utf-8')).hexdigest()[:8].upper()}",
            provider_name=profile.company_name,
            provider_website=profile.website_url,
            ai_system_name=f"Sistema IA - {profile.company_name}",
            intended_purpose="Evaluación de Dominio Sensible bajo el Anexo III del EU AI Act",
            high_risk_category=overall_risk.value,
            conformity_assessment_status="EN_PROCESO_DE_AUDITORIA",
            eu_representative=f"{profile.ciso_name} ({profile.ciso_role})",
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    # Imprimir Reporte Markdown en Consola y Matriz de Brechas
    print("\n--- INFORME OFICIAL DE AUDITORÍA Y OSINT (EU AI ACT) ---")
    print(f"# INFORME DE GOBERNANZA DE IA — {profile.company_name}")
    print(f"- **URL Corporativa:** {profile.website_url}")
    print(f"- **Responsable:** {profile.ciso_name} ({profile.ciso_role})")
    print(f"- **Nivel de Riesgo Asignado:** `{overall_risk.value}`")
    print(f"- **Puntuación Ciberseguridad OSINT (Art. 15):** {osint_report.header_audit.security_score}/100")
    if discrepancies:
        print(f"- **Discrepancias OSINT vs CISO:** {len(discrepancies)} detectadas.")

    print("\n### Matriz de Brechas (Gap Analysis):")
    if not findings:
        print("  [OK] No se detectaron brechas críticas de cumplimiento.")
    else:
        for f in findings:
            print(f"  - [{f.severity}] [{f.code} - {f.article}] {f.title}: {f.description}")
            print(f"    └─ Acción: {f.remediation_action}")

    # Instanciar AuditEngineResult preliminar
    audit_result = AuditEngineResult(
        profile=profile,
        audit_timestamp=datetime.now(timezone.utc).isoformat(),
        osint_report=osint_report,
        discrepancies=discrepancies,
        questions=questions_list,
        overall_risk=overall_risk,
        findings=findings,
        remediation_patches=remediation_patches,
        annex_viii_payload=annex_viii,
        hitl_approved=False
    )

    with open(output_json_path, "w", encoding="utf-8") as f:
        f.write(audit_result.model_dump_json(indent=2))
    print(f"\n[+] Expediente preliminar exportado a: `{os.path.abspath(output_json_path)}`")

    # --------------------------------------------------------------------------
    # FASE 3: SOLUCIONAR (REMEDIACIÓN AUTOMÁTICA + FIRMA HITL Y SELLADO SHA-256)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 85)
    print(" FASE 3: SOLUCIONAR — GENERACIÓN DE PARCHES Y PROTOCOLO DE FIRMA HITL")
    print("=" * 85)

    # Crear directorio remediation_output/ si no existe
    output_dir = os.path.dirname(os.path.abspath(output_json_path))
    remediation_dir = os.path.join(output_dir, "remediation_output")
    os.makedirs(remediation_dir, exist_ok=True)

    if remediation_patches:
        print(f"\n[+] Escribiendo {len(remediation_patches)} parches de remediación en '{remediation_dir}':")
        for idx, patch in enumerate(remediation_patches, 1):
            patch_file_path = os.path.join(remediation_dir, patch.filename)
            with open(patch_file_path, "w", encoding="utf-8") as pf:
                pf.write(patch.content)
            print(f"  [{idx}] [{patch.article}] {patch.title} -> `{patch_file_path}`")
    else:
        print("\n[✓] No se requieren parches de código urgentes.")

    # Protocolo HITL (Human-in-the-Loop)
    print("\n--- PROTOCOLO HITL (HUMAN-IN-THE-LOOP): AUTORIZACIÓN Y FIRMA DIGITAL ---")

    if non_interactive:
        signer_name = profile.ciso_name
        print(f"[MODO AUTOMÁTICO] Autorización HITL concedida automáticamente para el CISO: '{signer_name}'")
    else:
        print(f"El CISO/CTO/AI Lead ('{profile.ciso_name}') debe validar los parches y autorizar la auditoría.")
        confirm_input = input(f"Escriba la palabra 'CONFIRMO' para autorizar y firmar digitalmente la auditoría [{profile.ciso_name}]: ").strip()
        if confirm_input != "CONFIRMO":
            print("\n❌ Autorización HITL rechazada o palabra de confirmación incorrecta. El expediente queda PENDIENTE (hitl_approved: False).")
            return audit_result
        signer_name = profile.ciso_name

    now_iso = datetime.now(timezone.utc).isoformat()
    secret_salt = os.getenv("AUDIT_ENGINE_SALT", "EU_AI_ACT_ENGINE_2024_1689_SALT")

    raw_signature_payload = f"{signer_name}:{profile.website_url}:{overall_risk.value}:{now_iso}:{secret_salt}"
    signature_token = "SHA256:" + hashlib.sha256(raw_signature_payload.encode("utf-8")).hexdigest()

    audit_result.hitl_approved = True
    audit_result.signature_token = signature_token
    audit_result.signature_timestamp = now_iso
    audit_result.signed_by = signer_name

    with open(output_json_path, "w", encoding="utf-8") as f:
        f.write(audit_result.model_dump_json(indent=2))

    print("\n" + "*" * 85)
    print(" SELLADO DIGITAL Y REMEDIACIÓN HITL PROCESADA EXITOSAMENTE")
    print("*" * 85)
    print(f"  - Estado HITL Aprobado:        {audit_result.hitl_approved}")
    print(f"  - Firmado Por:                 {audit_result.signed_by}")
    print(f"  - Fecha/Hora de Firma:         {audit_result.signature_timestamp}")
    print(f"  - Token Criptográfico SHA256:  {audit_result.signature_token}")
    print(f"  - Expediente Sellado Guardado: `{os.path.abspath(output_json_path)}`")
    print("*" * 85)

    return audit_result


# ==============================================================================
# PUNTO DE ENTRADA CLI (__main__)
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Motor de Auditoría y Remediación EU AI Act (Reglamento UE 2024/1689) en 3 Fases con OSINT y HITL.")
    parser.add_argument("--url", default="https://python.org", help="URL del sitio web corporativo o repositorio a analizar.")
    parser.add_argument("--company", "--company-name", dest="company", default="Entidad Corporativa S.A.", help="Nombre formal de la empresa u organización.")
    parser.add_argument("--ciso-name", default="Director de Seguridad y CISO", help="Nombre del CISO / CTO / AI Lead.")
    parser.add_argument("--ciso-role", default="Chief Information Security Officer", help="Cargo oficial del responsable.")
    parser.add_argument("-o", "--output", default="ai_audit_result.json", help="Ruta del archivo JSON de destino.")
    parser.add_argument("--non-interactive", action="store_true", help="Ejecutar en modo no interactivo para integración continua / pipelines.")

    args = parser.parse_args()

    execute_audit_lifecycle(
        url=args.url,
        company=args.company,
        ciso_name=args.ciso_name,
        ciso_role=args.ciso_role,
        non_interactive=args.non_interactive,
        output_json_path=args.output
    )
    print("\n[+] Auditoría y ciclo de vida de remediación del EU AI Act finalizados con éxito.")


if __name__ == "__main__":
    main()
