"""
Cross-Normative Evidence Mesh for Quantigrade GCR.
Provides semantic evidence propagation and multi-regulatory deduplication across
DORA, NIS2, ENS, ISO 27001, CRA, and EU AI Act.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class CrossMappingResult:
    source_control: str
    source_framework: str
    status: str
    propagated_controls: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class GlobalCoverageSummary:
    primary_evidences_count: int
    total_satisfied_controls: int
    deduplication_savings_ratio: float
    frameworks_covered: List[str] = field(default_factory=list)


class CrossNormativeMesh:
    """
    Semantic equivalence router that prevents audit fatigue by mapping single evidence
    artifacts to multiple European and Spanish regulatory controls.
    """

    EQUIVALENCE_GRAPH: Dict[str, List[Dict[str, str]]] = {
        "DORA_BACKUP_01": [
            {"framework": "NIS2", "control_id": "NIS2_BACKUP_01", "name": "Gestion de copias de seguridad (Art. 21.2.c)"},
            {"framework": "ENS", "control_id": "ENS_OP_ACC_01", "name": "Copias de seguridad y continuidad (mp.info.3)"},
            {"framework": "ISO27001", "control_id": "ISO27001_A8_13", "name": "Copia de seguridad de la informacion"},
        ],
        "NIS2_INCIDENT_01": [
            {"framework": "DORA", "control_id": "DORA_INCIDENT_01", "name": "Clasificacion y reporte de incidentes TIC (Art. 19)"},
            {"framework": "ENS", "control_id": "ENS_OP_EXP_08", "name": "Notificacion de incidentes a CSIRT/CCN-CERT"},
            {"framework": "RGPD", "control_id": "RGPD_ART33", "name": "Notificacion de brechas de datos en 72h"},
        ],
        "AIACT_GOV_01": [
            {"framework": "OWASP_LLM", "control_id": "OWASP_LLM_01", "name": "Gobernanza y defensa frente a inyecciones"},
            {"framework": "ENS", "control_id": "ENS_SEG_01", "name": "Politica de seguridad para sistemas avanzados"},
            {"framework": "ISO27001", "control_id": "ISO27001_A5_8", "name": "Gestion de proyectos de IA y software"},
        ],
        "DORA_TPRM_01": [
            {"framework": "NIS2", "control_id": "NIS2_SUPPLY_CHAIN_01", "name": "Seguridad en la cadena de suministro TIC (Art. 21.2.d)"},
            {"framework": "ISO27001", "control_id": "ISO27001_A5_19", "name": "Seguridad de la informacion en relaciones con proveedores"},
            {"framework": "ENS", "control_id": "ENS_OP_EXT_01", "name": "Contratacion y acuerdos de nivel de servicio"},
        ],
    }

    def __init__(self):
        self._satisfied_controls: Dict[str, Dict[str, Any]] = {}
        self._primary_evidences_count: int = 0

    def get_equivalent_controls(self, control_id: str) -> List[Dict[str, str]]:
        """Returns all mapped equivalent controls for a given primary control."""
        # Check direct mapping
        if control_id in self.EQUIVALENCE_GRAPH:
            return list(self.EQUIVALENCE_GRAPH[control_id])

        # Check inverse mapping
        equivalents = []
        for root_id, mappings in self.EQUIVALENCE_GRAPH.items():
            for m in mappings:
                if m["control_id"] == control_id:
                    equivalents.append({"framework": "ROOT", "control_id": root_id, "name": "Control raiz equivalente"})
                    # Add sibling mappings
                    for sibling in mappings:
                        if sibling["control_id"] != control_id:
                            equivalents.append(sibling)
                    return equivalents
        return []

    def propagate_evidence(
        self,
        source_framework: str,
        control_id: str,
        status: str,
        evidence_data: Optional[Dict[str, Any]] = None,
    ) -> CrossMappingResult:
        """
        Ingests primary evidence and automatically fans out the compliance status
        to all equivalent controls across all target frameworks.
        """
        self._primary_evidences_count += 1
        evidence_data = evidence_data or {}

        # Record primary control
        self._satisfied_controls[control_id] = {
            "framework": source_framework,
            "status": status,
            "is_primary": True,
            "data": evidence_data,
        }

        propagated = []
        equivalents = self.get_equivalent_controls(control_id)

        for eq in equivalents:
            eq_id = eq["control_id"]
            eq_framework = eq["framework"]
            prop_record = {
                "framework": eq_framework,
                "control_id": eq_id,
                "status": status,
                "derived_from": control_id,
                "name": eq.get("name", ""),
            }
            propagated.append(prop_record)
            self._satisfied_controls[eq_id] = {
                "framework": eq_framework,
                "status": status,
                "is_primary": False,
                "derived_from": control_id,
                "data": evidence_data,
            }

        return CrossMappingResult(
            source_control=control_id,
            source_framework=source_framework,
            status=status,
            propagated_controls=propagated,
        )

    def get_global_coverage_summary(self) -> GlobalCoverageSummary:
        """Computes deduplication ratio and global satisfied controls."""
        total_satisfied = len(self._satisfied_controls)
        primary = max(self._primary_evidences_count, 1)
        savings_ratio = round(total_satisfied / primary, 2)

        frameworks = sorted(list({c.get("framework", "") for c in self._satisfied_controls.values()}))

        return GlobalCoverageSummary(
            primary_evidences_count=self._primary_evidences_count,
            total_satisfied_controls=total_satisfied,
            deduplication_savings_ratio=savings_ratio,
            frameworks_covered=frameworks,
        )
