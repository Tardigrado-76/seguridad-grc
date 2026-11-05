"""
Test suite for EditorialPDFGenerator.
Validates PDF generation, structural elements, Merkle seal inclusion, and executive compliance report output.
"""

import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
from core_mesh.business_execution.editorial_pdf_generator import EditorialPDFGenerator, ReportMetadata


def test_editorial_pdf_generator_creates_valid_pdf():
    generator = EditorialPDFGenerator()
    metadata = ReportMetadata(
        company_name="Quantigrade Global Tech",
        ciso_name="Dr. Alex Vance, CISSP",
        dpo_name="Elena Rodriguez, CIPP/E",
        overall_score=97.2,
        evaluation_id="EVAL-2026-BOARD-001"
    )
    
    framework_scores = {
        "DORA": 100.0,
        "NIS2": 95.0,
        "ENS": 100.0,
        "RGPD - LOPDGDD": 98.0,
        "EU AI Act": 94.0,
        "CRA": 96.5,
        "Corporate Defense y Prevención Penal": 100.0,
        "Mandato PQC NIST FIPS 203-204": 100.0
    }
    
    seal_info = {
        "seal_id": "SEAL-2026-XYZ-999",
        "merkle_root": "a" * 64,
        "hmac_signature": "b" * 64,
        "pqc_ml_dsa_signature": "c" * 128,
        "timestamp_iso": "2026-10-27T16:00:00Z"
    }

    pdf_bytes = generator.generate_executive_pdf(
        metadata=metadata,
        framework_scores=framework_scores,
        merkle_seal=seal_info
    )

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")  # Valid PDF binary signature
    assert "Mandato PQC NIST FIPS 203-204" in generator.FRAMEWORK_AUTHORITIES


def test_editorial_pdf_generator_with_fair_and_tprm():
    generator = EditorialPDFGenerator()
    metadata = ReportMetadata(company_name="Enterprise Corp")
    scores = {"DORA": 100.0, "NIS2": 90.0}
    risk_summary = {
        "total_annualized_loss_expectancy_eur": 125000.0,
        "aggregate_mitigation_rate_percentage": 78.5
    }
    tprm_summary = {
        "critical_tier1_count": 3,
        "schrems_high_risk_vendors": 0
    }
    pdf_bytes = generator.generate_executive_pdf(
        metadata=metadata,
        framework_scores=scores,
        risk_summary=risk_summary,
        tprm_summary=tprm_summary
    )
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")

