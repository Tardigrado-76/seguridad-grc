#!/usr/bin/env python3
"""
test_iso27001_soc2_evaluator.py
TDD Suite for ISO27001SOC2Mapper polymorphism and standalone evaluate() support.
"""

import sys
from pathlib import Path

# Add compliance manager to path
comp_mgr = Path(r"e:\PROYECTOS IA\PRODUCTION READY\100\GITHUB\QUANTIGRADE GRC")
if str(comp_mgr) not in sys.path:
    sys.path.insert(0, str(comp_mgr))


def test_iso27001_soc2_mapper_standalone_evaluate(tmp_path):
    """Verify ISO27001SOC2Mapper can be instantiated with target_path and evaluated standalone."""
    from src.evaluators.iso27001_soc2_mapper import ISO27001SOC2Mapper

    # Populate compliant assets for underlying evaluators
    (tmp_path / "credential_guard_hardening.ps1").write_text("# LSA Protection Enforced", encoding="utf-8")
    (tmp_path / "file_integrity_fim_auditd.py").write_text("# FIM", encoding="utf-8")
    (tmp_path / "iam_rbac_access_policy.py").write_text("# IAM", encoding="utf-8")
    (tmp_path / "tls_fips_crypto_cert.py").write_text("# Crypto TLS", encoding="utf-8")
    (tmp_path / "dora_ict_risk_framework.py").write_text("# DORA Risk", encoding="utf-8")
    (tmp_path / "dora_incident_management.py").write_text("# DORA Incident", encoding="utf-8")
    (tmp_path / "dora_resilience_testing.py").write_text("# TLPT", encoding="utf-8")
    (tmp_path / "dora_third_party_risk.py").write_text("# Vendor Risk", encoding="utf-8")
    (tmp_path / "dora_threat_intelligence_sharing.py").write_text("# Threat Intel", encoding="utf-8")
    (tmp_path / "dora_immutable_log_verif.py").write_text("# Log verif", encoding="utf-8")
    (tmp_path / "nis2_csirt_incident_reporting.py").write_text("# CSIRT", encoding="utf-8")
    (tmp_path / "nis2_supply_chain_security.py").write_text("# Supply Chain", encoding="utf-8")
    (tmp_path / "nis2_vulnerability_disclosure.py").write_text("# CVD", encoding="utf-8")
    (tmp_path / "nis2_crypto_policy.py").write_text("# Cryptography", encoding="utf-8")
    (tmp_path / "nis2_bunker_backup_disaster.py").write_text("# Backup", encoding="utf-8")
    (tmp_path / "cyclonedx_sbom.json").write_text('{"bomFormat": "CycloneDX"}', encoding="utf-8")
    (tmp_path / "cisa_kev_checker.py").write_text("# KEV audit", encoding="utf-8")
    (tmp_path / "ai_compliance_engine.py").write_text("# AI compliance", encoding="utf-8")

    mapper = ISO27001SOC2Mapper(str(tmp_path), "TEST_CORP")

    res = mapper.evaluate()
    assert res.framework_name == "ISO27001_SOC2"
    assert res.total_rules > 0
    assert res.compliance_score >= 90.0
    assert res.passed_rules > 0


def test_iso27001_soc2_mapper_dict_input(tmp_path):
    """Verify backward compatibility with dict of EvaluatorResult."""
    from src.evaluators.dora import DORAEvaluator
    from src.evaluators.ens_high import ENSHighEvaluator
    from src.evaluators.iso27001_soc2_mapper import ISO27001SOC2Mapper

    (tmp_path / "credential_guard_hardening.ps1").write_text("# LSA Protection Enforced", encoding="utf-8")
    (tmp_path / "file_integrity_fim_auditd.py").write_text("# FIM", encoding="utf-8")
    (tmp_path / "iam_rbac_access_policy.py").write_text("# IAM", encoding="utf-8")
    (tmp_path / "tls_fips_crypto_cert.py").write_text("# Crypto TLS", encoding="utf-8")
    (tmp_path / "dora_ict_risk_framework.py").write_text("# DORA Risk", encoding="utf-8")
    (tmp_path / "dora_incident_management.py").write_text("# DORA Incident", encoding="utf-8")
    (tmp_path / "dora_resilience_testing.py").write_text("# TLPT", encoding="utf-8")
    (tmp_path / "dora_third_party_risk.py").write_text("# Vendor Risk", encoding="utf-8")
    (tmp_path / "dora_threat_intelligence_sharing.py").write_text("# Threat Intel", encoding="utf-8")
    (tmp_path / "dora_immutable_log_verif.py").write_text("# Log verif", encoding="utf-8")

    dora_res = DORAEvaluator(str(tmp_path), "TEST_CORP").evaluate()
    ens_res = ENSHighEvaluator(str(tmp_path), "TEST_CORP").evaluate()

    mapper = ISO27001SOC2Mapper({"DORA": dora_res, "ENS": ens_res})
    crosswalk = mapper.generate_crosswalk()

    assert "iso27001" in crosswalk
    assert "soc2" in crosswalk
    assert crosswalk["hardening_certified"] is True
    assert crosswalk["iso27001"]["score"] >= 90.0
