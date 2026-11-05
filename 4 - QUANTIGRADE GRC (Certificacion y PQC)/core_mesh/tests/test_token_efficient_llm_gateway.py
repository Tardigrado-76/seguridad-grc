import pytest
from core_mesh.operational.token_efficient_llm_gateway import TokenEfficientLLMGateway

def test_pre_aggregate_context_list_summary():
    gateway = TokenEfficientLLMGateway()
    raw_findings = [
        {"id": f"VULN-{i}", "category": "OWASP_API", "severity": "CRITICAL" if i % 2 == 0 else "MEDIUM"}
        for i in range(100)
    ]
    digest = gateway.pre_aggregate_context(raw_findings)
    assert digest["type"] == "LIST_SUMMARY"
    assert digest["total_count"] == 100
    assert digest["category_distribution"]["OWASP_API"] == 100
    assert digest["severity_distribution"]["CRITICAL"] == 50
    assert digest["severity_distribution"]["MEDIUM"] == 50
    assert len(digest["sample_elements"]) == 2

def test_pre_aggregate_context_dict_and_text():
    gateway = TokenEfficientLLMGateway()
    # Dict test
    raw_dict = {"api_name": "AuthService", "version": "v1.2", "active": True, "details": "long text..."}
    d_digest = gateway.pre_aggregate_context(raw_dict)
    assert d_digest["type"] == "DICT_SUMMARY"
    assert d_digest["total_keys"] == 4
    assert "api_name" in d_digest["summary"]

    # Text test
    raw_text = "\n".join([f"Log line {i}: access granted" for i in range(50)])
    t_digest = gateway.pre_aggregate_context(raw_text)
    assert t_digest["type"] == "TEXT_SUMMARY"
    assert t_digest["total_lines"] == 50

def test_semantic_cache_hit_and_token_savings():
    gateway = TokenEfficientLLMGateway()
    prompt = "Evaluar vulnerabilidad de autenticación"
    context = [{"type": "auth_header", "status": "missing"}]

    # First call - cache miss
    res1 = gateway.execute_query(prompt, raw_context=context)
    assert res1["cache_hit"] is False
    assert res1["provider_used"] == "DETERMINISTIC_SOVEREIGN_FALLBACK"
    assert res1["actual_tokens_sent"] > 0

    # Second call - cache hit
    res2 = gateway.execute_query(prompt, raw_context=context)
    assert res2["cache_hit"] is True
    assert res2["provider_used"] == "SEMANTIC_CACHE"
    assert res2["actual_tokens_sent"] == 0
    assert res2["savings_percentage"] == 100.0

def test_token_reduction_calculation():
    gateway = TokenEfficientLLMGateway()
    # 500 detailed items would normally take ~50,000 characters (~12,500 tokens)
    large_context = [
        {"id": f"EVENT-{i}", "description": "High volume transaction audit log with extensive metadata", "severity": "HIGH"}
        for i in range(500)
    ]
    res = gateway.execute_query("Resumir alertas críticas", raw_context=large_context)
    assert res["raw_tokens_expected"] > 5000
    assert res["actual_tokens_sent"] < 500
    assert res["savings_percentage"] > 90.0

def test_mock_response_and_free_provider_routing():
    gateway = TokenEfficientLLMGateway()
    res = gateway.execute_query(
        "Diagnóstico DORA",
        raw_context={"status": "OK"},
        mock_response="Diagnóstico DORA completado satisfactoriamente."
    )
    assert res["provider_used"] == "MOCK_INFERENCE"
    assert "satisfactoriamente" in res["response"]
