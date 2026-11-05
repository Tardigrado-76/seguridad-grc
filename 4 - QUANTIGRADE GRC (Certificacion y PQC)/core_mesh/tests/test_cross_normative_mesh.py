"""
Tests for CrossNormativeMesh: Cross-regulatory evidence propagation and deduplication.
"""
import pytest
from core_mesh.operational.cross_normative_mesh import (
    CrossNormativeMesh,
    CrossMappingResult,
    GlobalCoverageSummary,
)


def test_cross_normative_mesh_equivalences():
    mesh = CrossNormativeMesh()
    equivalents = mesh.get_equivalent_controls("DORA_BACKUP_01")
    assert len(equivalents) >= 2
    frameworks = [eq["framework"] for eq in equivalents]
    assert "NIS2" in frameworks
    assert "ENS" in frameworks or "ISO27001" in frameworks


def test_propagate_evidence():
    mesh = CrossNormativeMesh()
    result = mesh.propagate_evidence(
        source_framework="DORA",
        control_id="DORA_BACKUP_01",
        status="PASSED",
        evidence_data={"last_backup_timestamp": "2026-10-27T12:00:00Z", "immutable_vault": True},
    )

    assert result.source_control == "DORA_BACKUP_01"
    assert result.status == "PASSED"
    assert len(result.propagated_controls) >= 2
    # Verify each propagated control carries the source status
    for prop in result.propagated_controls:
        assert prop["status"] == "PASSED"
        assert "derived_from" in prop


def test_global_coverage_summary():
    mesh = CrossNormativeMesh()
    # Ingest 3 primary evidences
    mesh.propagate_evidence("DORA", "DORA_BACKUP_01", "PASSED", {"rpo_hours": 1})
    mesh.propagate_evidence("NIS2", "NIS2_INCIDENT_01", "PASSED", {"csirt_notified": True})
    mesh.propagate_evidence("EU_AI_ACT", "AIACT_GOV_01", "PASSED", {"model_card_present": True})

    summary = mesh.get_global_coverage_summary()
    assert summary.primary_evidences_count == 3
    assert summary.total_satisfied_controls >= 6
    assert summary.deduplication_savings_ratio >= 1.5
