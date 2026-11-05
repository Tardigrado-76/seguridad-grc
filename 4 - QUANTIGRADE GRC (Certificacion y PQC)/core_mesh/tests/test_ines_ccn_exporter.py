"""
Tests for InesCcnExporter: Mapping evidence to official ENS (RD 311/2022) & INES CCN-STIC 808 export.
"""
import pytest
from core_mesh.business_execution.ines_ccn_exporter import (
    InesCcnExporter,
    EnsMaturityLevel,
    InesExportPayload,
)


def test_map_framework_evidence_to_ens():
    exporter = InesCcnExporter()
    evidences = {
        "DORA_BACKUP_01": {"status": "PASSED", "details": "Backup inmutable verificado"},
        "NIS2_INCIDENT_01": {"status": "PASSED", "details": "Procedimiento CSIRT activo"},
        "ISO27001_A5_19": {"status": "PASSED", "details": "Auditoria de proveedores completa"},
    }

    mapped = exporter.map_evidence_to_ens(evidences)
    assert "org" in mapped
    assert "op" in mapped
    assert "mp" in mapped
    
    # Check that mp.info.3 (Copias) is populated from DORA_BACKUP_01
    assert mapped["mp"]["mp.info.3"]["compliance_score"] == 100.0


def test_calculate_ens_maturity_levels():
    exporter = InesCcnExporter()
    ens_scores = {
        "org.1": 100.0,
        "op.acc.1": 95.0,
        "mp.info.3": 100.0,
        "mp.si.1": 40.0,
    }

    maturities = exporter.calculate_maturity_levels(ens_scores)
    assert maturities["org.1"] == EnsMaturityLevel.NIVEL_5_OPTIMIZADO
    assert maturities["op.acc.1"] == EnsMaturityLevel.NIVEL_4_GESTIONADO
    assert maturities["mp.si.1"] == EnsMaturityLevel.NIVEL_2_REPETIBLE


def test_generate_ines_export_payload():
    exporter = InesCcnExporter(organism_name="Ministerio para la Transformacion Digital", dir3_code="E05073401")
    evidences = {
        "DORA_BACKUP_01": {"status": "PASSED"},
        "NIS2_INCIDENT_01": {"status": "PASSED"},
    }

    payload = exporter.generate_ines_export(evidences, category="ALTA")
    assert isinstance(payload, InesExportPayload)
    assert payload.dir3_code == "E05073401"
    assert payload.category == "ALTA"
    assert payload.global_maturity_index >= 3.0
    assert "marco_organizativo" in payload.ines_schema_data
    assert "marco_operacional" in payload.ines_schema_data
    assert "medidas_proteccion" in payload.ines_schema_data
    assert len(payload.merkle_root_seal) == 64
