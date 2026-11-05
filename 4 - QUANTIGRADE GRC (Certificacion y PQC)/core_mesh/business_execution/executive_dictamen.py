from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from .merkle_bunker import EvidenceSeal

class ExecutiveDictamenGenerator:
    """Generates board-level formal compliance dictamens and certification reports."""

    @classmethod
    def generate_markdown_dictamen(
        cls,
        company_name: str,
        framework_name: str,
        compliance_score: float,
        rag_status: str,
        total_rules: int,
        passed_rules: int,
        failed_rules: int,
        seal: Optional[EvidenceSeal] = None,
        financial_summary: Optional[Dict[str, Any]] = None
    ) -> str:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        badge = {
            "GREEN": "🟢 CONFORME (Apto para Certificación / Riesgo Bajo)",
            "AMBER": "🟡 CONFORME CONDICIONAL (Plan de Remediación Requerido)",
            "RED": "🔴 NO CONFORME (Bloqueo Regulatorio / Riesgo Crítico)"
        }.get(rag_status, "⚪ EN REVISIÓN")

        seal_sec = ""
        if seal:
            seal_sec = f"""
## 🛡️ Certificación Criptográfica de Evidencias (SLSA L3+)
- **Identificador de Custodia:** `{seal.seal_id}`
- **Raíz del Árbol de Merkle (SHA-256):** `{seal.merkle_root}`
- **Total de Evidencias Inmutables:** {seal.leaf_count}
- **Firma Digital HMAC:** `{seal.hmac_signature[:24]}...`
"""

        fin_sec = ""
        if financial_summary:
            fin_sec = f"""
## 💰 Exposición Financiera y Cuantificación de Riesgo
- **Exposición Máxima a Sanciones:** {financial_summary.get('max_potential_fine_formatted', 'N/A')}
- **Riesgo Residual Estimado:** {financial_summary.get('residual_risk_eur_formatted', 'N/A')}
- **Presupuesto de Remediación Requerido:** {financial_summary.get('remediation_budget_eur_formatted', 'N/A')}
- **Retorno de Inversión en Compliance (ROCI):** {financial_summary.get('roci_ratio', 'N/A')}
"""

        return f"""# 🏛️ Dictamen Ejecutivo de Cumplimiento Regulatorio y Gobernanza (GCR)

**Entidad Auditada:** {company_name}  
**Marco de Cumplimiento:** {framework_name}  
**Fecha de Emisión:** {now_str}  
**Veredicto Formal:** {badge}

---

## 1. Resumen de la Evaluación
- **Puntuación de Cumplimiento:** **{compliance_score:.1f}%**
- **Estado RAG:** **{rag_status}**
- **Reglas Evaluadas:** {total_rules}
- **Reglas Cumplidas:** {passed_rules}
- **Reglas No Conformes:** {failed_rules}

{seal_sec}
{fin_sec}

## 2. Dictamen del Comité de Cumplimiento
Habiéndose examinado las evidencias técnicas, verificaciones criptográficas e informes de auditoría, se certifica que la entidad presenta un nivel de madurez técnica y jurídica acorde con las exigencias del marco **{framework_name}**.

---
*Documento generado automáticamente por la Plataforma GCR Quantigrade.*
"""
