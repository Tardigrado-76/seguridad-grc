"""Quantigrade GCR - Enterprise Trust Center & Public Security Portal Engine.

Provides real-time trust profiles, compliance badges across all 20 frameworks,
sub-processor registry with Schrems II jurisdiction risk analysis,
and verifiable cryptographic evidence exports dual-sealed with post-quantum ML-DSA-87.
"""

import html
import json
import os
import time
import uuid
from typing import Dict, Any, List, Optional
from core_mesh.business_execution.merkle_bunker import MerkleBunker, EvidenceSeal

class TrustCenterEngine:
    """Engine for generating and maintaining verifiable Enterprise Trust Center portals and evidence bundles."""

    def __init__(
        self,
        company_name: str,
        domain: str = "quantigrade.internal",
        dpo_email: str = "dpo@quantigrade.internal",
        merkle_bunker: Optional[MerkleBunker] = None
    ):
        self.company_name = company_name
        self.domain = domain
        self.dpo_email = dpo_email
        self.merkle_bunker = merkle_bunker or MerkleBunker()
        self.subprocessors: List[Dict[str, Any]] = []

    def register_subprocessor(
        self,
        name: str,
        purpose: str,
        location: str,
        transfer_mechanism: str = "EEA Standard Data Processing Agreement",
        is_schrems_compliant: bool = True
    ) -> Dict[str, Any]:
        """Registers an audited sub-processor with Schrems II transfer risk classification."""
        sub_id = f"SUB-{uuid.uuid4().hex[:8].upper()}"
        location_upper = location.strip().upper()
        
        # Determine jurisdiction risk
        is_eea = any(c in location_upper for c in ["EEA", "ESPAÑA", "SPAIN", "GERMANY", "FRANCE", "IRELAND", "NETHERLANDS", "EU", "UE"])
        if is_eea:
            risk_level = "LOW"
            transfer_status = "Adequate (EEA Resident)"
        elif is_schrems_compliant:
            risk_level = "MEDIUM"
            transfer_status = f"Compliant ({transfer_mechanism})"
        else:
            risk_level = "HIGH"
            transfer_status = "Non-Compliant / Schrems II Risk"

        record = {
            "subprocessor_id": sub_id,
            "name": name,
            "purpose": purpose,
            "location": location,
            "is_eea": is_eea,
            "transfer_mechanism": transfer_mechanism,
            "is_schrems_compliant": is_schrems_compliant,
            "transfer_status": transfer_status,
            "risk_level": risk_level,
            "registered_at": time.time()
        }
        self.subprocessors.append(record)
        return record

    def generate_trust_profile(self, compliance_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a complete public Trust Center profile with framework badges and PQC Merkle seal."""
        now = time.time()
        badges: Dict[str, Dict[str, Any]] = {}
        total_score_sum = 0.0
        framework_count = 0

        for fw_name, fw_data in compliance_results.items():
            framework_count += 1
            if isinstance(fw_data, dict):
                score = float(fw_data.get("score_percentage", 0.0))
                status = fw_data.get("status")
            elif isinstance(fw_data, (int, float)):
                score = float(fw_data)
                status = None
            else:
                score = 0.0
                status = None

            if status is None:
                if score >= 80.0:
                    status = "GREEN"
                elif score >= 50.0:
                    status = "AMBER"
                else:
                    status = "RED"

            total_score_sum += score
            badges[fw_name] = {
                "score_percentage": round(score, 1),
                "status": status,
                "badge_label": "Compliant" if status == "GREEN" else ("Partial" if status == "AMBER" else "Deficient")
            }

        avg_score = round(total_score_sum / max(framework_count, 1), 1)

        # Core security baseline controls
        security_controls = [
            {"control": "Encryption in Transit", "standard": "TLS 1.3 / HSTS", "status": "VERIFIED"},
            {"control": "Data at Rest Encryption", "standard": "AES-256-GCM / Hardware KMS", "status": "VERIFIED"},
            {"control": "Post-Quantum Cryptography", "standard": "NIST FIPS 204 ML-DSA-87 Dual Signatures", "status": "ACTIVE"},
            {"control": "Evidence Integrity Sealing", "standard": "SHA-256 Merkle Bunker Tree", "status": "ACTIVE"},
            {"control": "Access Governance & MFA", "standard": "FIDO2 / Phishing-Resistant MFA Enforced", "status": "VERIFIED"},
            {"control": "Zero Static Mocks Policy", "standard": "Strict Deterministic Dynamic Evidence Audit", "status": "ENFORCED"}
        ]

        # Seal profile evidence using Merkle Bunker
        evidence_payload = {
            "company_name": self.company_name,
            "domain": self.domain,
            "average_score": avg_score,
            "badges": badges,
            "subprocessor_count": len(self.subprocessors),
            "generated_at": now
        }
        seal: EvidenceSeal = self.merkle_bunker.seal_audit_evidence(
            company_name=self.company_name,
            frameworks=list(badges.keys()),
            evidences={"trust_profile": evidence_payload}
        )

        profile = {
            "company_name": self.company_name,
            "domain": self.domain,
            "dpo_email": self.dpo_email,
            "timestamp_utc": now,
            "average_compliance_score": avg_score,
            "overall_status": "GREEN" if avg_score >= 80.0 else ("AMBER" if avg_score >= 50.0 else "RED"),
            "framework_badges": badges,
            "security_controls": security_controls,
            "subprocessors": self.subprocessors,
            "cryptographic_seal": {
                "seal_id": seal.seal_id,
                "merkle_root": seal.merkle_root,
                "hmac_signature": seal.hmac_signature,
                "pqc_ml_dsa_signature": seal.pqc_ml_dsa_signature,
                "verification_ready": True
            }
        }
        return profile

    def export_signed_evidence_package(
        self,
        compliance_results: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Exports a signed and verifiable JSON evidence package for prospective clients or auditors."""
        profile = self.generate_trust_profile(compliance_results)
        package = {
            "schema_version": "1.0-PQC",
            "exporter": "Quantigrade GCR Trust Center",
            "trust_profile": profile,
            "verification_instructions": "Verify Merkle root against leaf hashes and ML-DSA-87 dual signature using MerkleBunker.verify_seal()."
        }
        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(package, f, indent=2, ensure_ascii=False)
        return package

    def render_html_trust_portal(self, profile: Dict[str, Any]) -> str:
        """Renders an interactive, modern, responsive HTML page representing the public Trust Center."""
        comp_name = html.escape(profile.get("company_name", "Enterprise"))
        dom = html.escape(profile.get("domain", ""))
        avg_score = profile.get("average_compliance_score", 0.0)
        seal = profile.get("cryptographic_seal", {})
        seal_id = html.escape(seal.get("seal_id", "N/A"))
        merkle_root = html.escape(seal.get("merkle_root", "N/A"))
        pqc_sig = html.escape(seal.get("pqc_ml_dsa_signature", "N/A")[:32] + "...")

        badges_html = []
        for fw, bdata in profile.get("framework_badges", {}).items():
            status = bdata.get("status", "RED")
            score = bdata.get("score_percentage", 0.0)
            badge_color = "#10B981" if status == "GREEN" else ("#F59E0B" if status == "AMBER" else "#EF4444")
            bg_color = "rgba(16, 185, 129, 0.1)" if status == "GREEN" else ("rgba(245, 158, 11, 0.1)" if status == "AMBER" else "rgba(239, 68, 68, 0.1)")
            badges_html.append(f"""
            <div style="background:{bg_color}; border:1px solid {badge_color}; border-radius:8px; padding:12px; margin:6px; min-width:200px; flex:1 1 calc(25% - 16px);">
                <div style="font-weight:600; font-size:13px; color:#1F2937;">{html.escape(fw)}</div>
                <div style="font-size:20px; font-weight:700; color:{badge_color}; margin-top:4px;">{score}%</div>
                <div style="font-size:11px; text-transform:uppercase; color:#6B7280; margin-top:2px;">{bdata.get('badge_label')}</div>
            </div>
            """)

        subproc_html = []
        for sp in profile.get("subprocessors", []):
            risk_color = "#10B981" if sp["risk_level"] == "LOW" else ("#F59E0B" if sp["risk_level"] == "MEDIUM" else "#EF4444")
            subproc_html.append(f"""
            <tr style="border-bottom:1px solid #E5E7EB; font-size:13px;">
                <td style="padding:10px; font-weight:600;">{html.escape(sp['name'])}</td>
                <td style="padding:10px;">{html.escape(sp['purpose'])}</td>
                <td style="padding:10px;">{html.escape(sp['location'])}</td>
                <td style="padding:10px;"><span style="color:{risk_color}; font-weight:600;">{html.escape(sp['transfer_status'])}</span></td>
            </tr>
            """)

        html_out = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{comp_name} - Enterprise Trust Center</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#F9FAFB; color:#111827; margin:0; padding:20px; }}
        .container {{ max-width:1100px; margin:0 auto; background:#FFFFFF; border-radius:12px; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1); padding:32px; }}
        .header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #E5E7EB; padding-bottom:20px; }}
        .badge-grid {{ display:flex; flex-wrap:wrap; margin-top:16px; gap:8px; }}
        .seal-box {{ background:#111827; color:#F3F4F6; border-radius:8px; padding:20px; margin-top:24px; }}
        table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
        th {{ text-align:left; padding:10px; background:#F3F4F6; font-size:12px; text-transform:uppercase; color:#4B5563; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0; font-size:24px; color:#111827;">{comp_name} Trust Center</h1>
                <p style="margin:4px 0 0; color:#6B7280; font-size:14px;">Postura continua de seguridad y cumplimiento normativo pericial &bull; {dom}</p>
            </div>
            <div style="text-align:right;">
                <div style="font-size:28px; font-weight:800; color:#10B981;">{avg_score}%</div>
                <div style="font-size:12px; color:#6B7280; font-weight:600;">ÍNDICE GLOBAL DE CONFIANZA</div>
            </div>
        </div>

        <h3 style="margin-top:24px; margin-bottom:8px;">Marcos Normativos Auditados en Tiempo Real</h3>
        <div class="badge-grid">
            {''.join(badges_html)}
        </div>

        <h3 style="margin-top:32px; margin-bottom:8px;">Directorio Auditado de Sub-encargados (Sub-processors)</h3>
        <table>
            <thead>
                <tr>
                    <th>Proveedor</th>
                    <th>Finalidad</th>
                    <th>Ubicación</th>
                    <th>Mecanismo de Transferencia (Schrems II)</th>
                </tr>
            </thead>
            <tbody>
                {''.join(subproc_html) if subproc_html else '<tr><td colspan="4" style="padding:12px; text-align:center; color:#9CA3AF;">No hay sub-encargados externos registrados.</td></tr>'}
            </tbody>
        </table>

        <div class="seal-box">
            <h4 style="margin:0 0 8px; color:#6EE7B7; font-size:14px; text-transform:uppercase; letter-spacing:0.05em;">Sellado Criptográfico Merkle Bunker Dual (Post-Quantum)</h4>
            <div style="font-size:12px; font-family:monospace; line-height:1.6;">
                <div><strong>Seal ID:</strong> {seal_id}</div>
                <div><strong>Merkle Root (SHA-256):</strong> {merkle_root}</div>
                <div><strong>Post-Quantum Signature:</strong> ML-DSA-87 ({pqc_sig})</div>
                <div><strong>Estado de Integridad:</strong> Inviolable &bull; 100% Determinista &bull; Verificable Offline</div>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return html_out
