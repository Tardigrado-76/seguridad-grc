import pytest
from core_mesh.operational.external_threat_intel_feed import ExternalThreatIntelFeed

def test_enrich_cves_detects_log4shell_in_cisa_kev():
    feed = ExternalThreatIntelFeed()
    res = feed.enrich_cves(["CVE-2021-44228", "CVE-2024-99999"])
    assert res["total_cves_scanned"] == 2
    assert res["actively_exploited_count"] == 1
    assert res["requires_immediate_incident_declaration"] is True

    log4j = next(f for f in res["findings"] if f["cve_id"] == "CVE-2021-44228")
    assert log4j["in_cisa_kev"] is True
    assert log4j["escalated_severity"] == "CRITICAL"
    assert "NIS2" in log4j["regulatory_mandate"]

def test_enrich_cves_unknown_cve():
    feed = ExternalThreatIntelFeed()
    res = feed.enrich_cves(["CVE-2025-0001"])
    assert res["actively_exploited_count"] == 0
    assert res["requires_immediate_incident_declaration"] is False
    assert res["findings"][0]["escalated_severity"] == "STANDARD"

def test_inspect_certificate_transparency():
    feed = ExternalThreatIntelFeed()
    report = feed.inspect_certificate_transparency("quantigrade.eu")
    assert report["domain"] == "quantigrade.eu"
    assert report["total_certificates_found"] == 2
    assert report["wildcard_certificates_count"] == 1
    assert report["suspicious_assets_count"] == 1
    assert "DORA Art. 9.4" in report["shadow_it_alerts"][0]["compliance_impact"]

def test_normalize_financial_risk_to_eur():
    feed = ExternalThreatIntelFeed()
    # 10,800,000 USD at 1.08 rate = 10,000,000 EUR
    norm = feed.normalize_financial_risk_to_eur(10800000.0, "USD")
    assert norm["original_amount"] == 10800000.0
    assert norm["normalized_amount_eur"] == 10000000.0
    assert norm["regulatory_thresholds"]["exceeds_dora_threshold"] is True

def test_custom_kev_cache_extension():
    feed = ExternalThreatIntelFeed(local_kev_cache={
        "CVE-2026-1111": {
            "vendor": "Cisco",
            "product": "IOS-XE",
            "required_action": "Isolate switch."
        }
    })
    res = feed.enrich_cves(["CVE-2026-1111"])
    assert res["actively_exploited_count"] == 1
    assert res["findings"][0]["vendor"] == "Cisco"
