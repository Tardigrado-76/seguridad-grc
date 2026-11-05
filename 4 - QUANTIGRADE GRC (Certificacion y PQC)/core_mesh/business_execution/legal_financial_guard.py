"""
Legal & Financial Guard for Quantigrade GCR.
Actuarial calculation of regulatory fines (DORA, NIS2, RGPD), Board of Directors liability
(Spanish Criminal Code Art. 31 bis CP & NIS2 Art. 20), and Remediation ROI.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class SanctionCalculation:
    framework: str
    turnover_eur: float
    severity: str
    max_statutory_fine_eur: float
    estimated_fine_eur: float
    legal_basis: str


@dataclass
class ExecutiveLiabilityReport:
    liability_level: str
    nis2_art20_disqualification_risk: bool
    criminal_code_31bis_exposure: bool
    affected_executives: List[str]
    mitigation_recommendations: List[str] = field(default_factory=list)


@dataclass
class RemediationRoiReport:
    remediation_cost_eur: float
    potential_sanction_eur: float
    inspection_probability: float
    expected_loss_eur: float
    net_savings_eur: float
    roi_ratio: float


class LegalFinancialGuard:
    """
    Financial and legal defense engine for Quantigrade GCR.
    Translates technical compliance gaps into direct executive balance sheet exposure.
    """

    SEVERITY_FACTORS = {
        "LOW": 0.25,
        "MODERATE": 0.50,
        "HIGH": 0.75,
        "CRITICAL": 1.00,
    }

    def calculate_dora_sanction(self, turnover_eur: float, severity: str = "HIGH") -> SanctionCalculation:
        """
        Calculates administrative fines under DORA Art. 50.
        Cap: Up to 10,000,000 EUR or 2% of total worldwide annual turnover, whichever is higher.
        """
        sev_factor = self.SEVERITY_FACTORS.get(severity.upper(), 0.50)
        percentage_cap = turnover_eur * 0.02
        statutory_cap = max(10_000_000.0, percentage_cap)
        estimated = statutory_cap * sev_factor

        return SanctionCalculation(
            framework="DORA",
            turnover_eur=turnover_eur,
            severity=severity.upper(),
            max_statutory_fine_eur=statutory_cap,
            estimated_fine_eur=estimated,
            legal_basis="DORA Reglamento (UE) 2022/2554, Articulo 50",
        )

    def calculate_nis2_sanction(
        self, turnover_eur: float, entity_type: str = "ESSENTIAL", severity: str = "HIGH"
    ) -> SanctionCalculation:
        """
        Calculates administrative fines under NIS2 Art. 34.
        Essential entities: Up to 10,000,000 EUR or 2% of total annual turnover.
        Important entities: Up to 7,000,000 EUR or 1.4% of total annual turnover.
        """
        sev_factor = self.SEVERITY_FACTORS.get(severity.upper(), 0.50)
        is_essential = entity_type.upper() == "ESSENTIAL"

        if is_essential:
            statutory_cap = max(10_000_000.0, turnover_eur * 0.02)
            legal_basis = "Directiva (UE) 2022/2555 (NIS2), Articulo 34.4 (Entidades Esenciales)"
        else:
            statutory_cap = max(7_000_000.0, turnover_eur * 0.014)
            legal_basis = "Directiva (UE) 2022/2555 (NIS2), Articulo 34.5 (Entidades Importantes)"

        estimated = statutory_cap * sev_factor

        return SanctionCalculation(
            framework="NIS2",
            turnover_eur=turnover_eur,
            severity=severity.upper(),
            max_statutory_fine_eur=statutory_cap,
            estimated_fine_eur=estimated,
            legal_basis=legal_basis,
        )

    def calculate_rgpd_sanction(self, turnover_eur: float, severity: str = "HIGH") -> SanctionCalculation:
        """
        Calculates administrative fines under RGPD Art. 83.
        Cap: Up to 20,000,000 EUR or 4% of total worldwide annual turnover, whichever is higher.
        """
        sev_factor = self.SEVERITY_FACTORS.get(severity.upper(), 0.50)
        statutory_cap = max(20_000_000.0, turnover_eur * 0.04)
        estimated = statutory_cap * sev_factor

        return SanctionCalculation(
            framework="RGPD",
            turnover_eur=turnover_eur,
            severity=severity.upper(),
            max_statutory_fine_eur=statutory_cap,
            estimated_fine_eur=estimated,
            legal_basis="Reglamento (UE) 2016/679 (RGPD), Articulo 83.5",
        )

    def evaluate_executive_liability(self, breaches: List[Dict[str, Any]]) -> ExecutiveLiabilityReport:
        """
        Evaluates civil and criminal exposure for the Board of Directors and C-level
        under Spanish Criminal Code Art. 31 bis CP and NIS2 Art. 20 (governance accountability).
        """
        critical_count = sum(1 for b in breaches if str(b.get("severity", "")).upper() == "CRITICAL")
        high_count = sum(1 for b in breaches if str(b.get("severity", "")).upper() == "HIGH")

        if critical_count >= 1 or high_count >= 2:
            level = "CRITICA" if critical_count >= 2 else "ALTA"
            disqualification = True
            criminal_exposure = True
        elif high_count == 1:
            level = "MEDIA"
            disqualification = False
            criminal_exposure = True
        else:
            level = "BAJA"
            disqualification = False
            criminal_exposure = False

        recommendations = [
            "Formalizar acta del Consejo de Administracion aprobando formalmente el presupuesto de ciberresiliencia (NIS2 Art. 20).",
            "Anclar los registros de verificacion en el Merkle Bunker con sellado de tiempo cualificado eIDAS 2.0 (defensa penal Art. 31 bis CP).",
            "Establecer formacion acreditada en ciberriesgos obligatoria para todos los miembros del Consejo.",
        ]

        return ExecutiveLiabilityReport(
            liability_level=level,
            nis2_art20_disqualification_risk=disqualification,
            criminal_code_31bis_exposure=criminal_exposure,
            affected_executives=["Consejo de Administracion", "Consejero Delegado (CEO)", "CISO", "Director de Cumplimiento"],
            mitigation_recommendations=recommendations,
        )

    def calculate_remediation_roi(
        self,
        remediation_cost_eur: float,
        potential_sanction_eur: float,
        inspection_probability: float = 0.25,
    ) -> RemediationRoiReport:
        """
        Calculates the Return on Investment (ROI) of remediation actions against potential fines.
        """
        expected_loss = potential_sanction_eur * inspection_probability
        net_savings = expected_loss - remediation_cost_eur
        roi = expected_loss / max(remediation_cost_eur, 1.0)

        return RemediationRoiReport(
            remediation_cost_eur=remediation_cost_eur,
            potential_sanction_eur=potential_sanction_eur,
            inspection_probability=inspection_probability,
            expected_loss_eur=expected_loss,
            net_savings_eur=net_savings,
            roi_ratio=round(roi, 2),
        )
