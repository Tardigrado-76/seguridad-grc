import pytest
from core_mesh.operational.multi_tenant_manager import MultiTenantManager

def test_register_tenant_with_byok(tmp_path):
    mgr = MultiTenantManager(base_storage_dir=str(tmp_path))
    custom_key = "my_super_secret_sovereign_key_12345"
    info = mgr.register_tenant("banco_santander", "Banco Santander S.A.", byok_key=custom_key, storage_quota_mb=100.0)

    assert info["tenant_id"] == "banco_santander"
    assert info["storage_quota_mb"] == 100.0
    assert len(info["key_fingerprint"]) == 16

def test_byok_encryption_and_decryption(tmp_path):
    mgr = MultiTenantManager(base_storage_dir=str(tmp_path))
    mgr.register_tenant("telefonica", "Telefónica España", byok_key="key_telef_987654321")

    secret_evidence = "Evidencia pericial confidencial de infraestructura 5G Core."
    envelope = mgr.encrypt_evidence_byok("telefonica", secret_evidence)

    assert envelope["ciphertext_b64"] != secret_evidence
    assert "auth_tag" in envelope

    decrypted = mgr.decrypt_evidence_byok("telefonica", envelope)
    assert decrypted == secret_evidence

def test_byok_tamper_detection(tmp_path):
    mgr = MultiTenantManager(base_storage_dir=str(tmp_path))
    mgr.register_tenant("inditex", "Inditex S.A.")

    envelope = mgr.encrypt_evidence_byok("inditex", "Reporte de auditoría interna")
    
    # Tamper with tag
    tampered_envelope = dict(envelope)
    tampered_envelope["auth_tag"] = "0" * 64

    with pytest.raises(PermissionError):
        mgr.decrypt_evidence_byok("inditex", tampered_envelope)

def test_tenant_quota_exceeded(tmp_path):
    mgr = MultiTenantManager(base_storage_dir=str(tmp_path))
    # 0.0001 MB is ~104 bytes
    mgr.register_tenant("small_tenant", "Micro PYME", storage_quota_mb=0.0001)

    with pytest.raises(MemoryError):
        # 500 bytes exceeds 104 bytes quota
        mgr.encrypt_evidence_byok("small_tenant", "X" * 500)

def test_rate_limiter_enforcement(tmp_path):
    mgr = MultiTenantManager(base_storage_dir=str(tmp_path))
    mgr.register_tenant("limited_corp", "Limited Corp", rate_limit_rpm=3)

    assert mgr.check_rate_limit("limited_corp") is True
    assert mgr.check_rate_limit("limited_corp") is True
    assert mgr.check_rate_limit("limited_corp") is True
    # 4th request in the same second exceeds 3 rpm limit
    assert mgr.check_rate_limit("limited_corp") is False
