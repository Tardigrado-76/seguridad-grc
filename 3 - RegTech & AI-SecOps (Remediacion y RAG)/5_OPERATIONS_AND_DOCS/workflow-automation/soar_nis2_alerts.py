import json
import os
import requests
from datetime import datetime, timezone

def trigger_nis2_alert(incident_details: dict):
    """
    SOAR Integration for NIS2 Compliance (Art. 23 - Early Warning).
    Sends high-priority alerts to CSIRT / Security Operations Center.
    """
    print(f"[{datetime.now(timezone.utc).isoformat()}] [SOAR] Processing NIS2 Alert...")
    
    webhook_url = os.getenv("CSIRT_WEBHOOK_URL", "http://localhost/mock-webhook")
    
    payload = {
        "framework": "NIS2",
        "article": "Art.23",
        "severity": "CRITICAL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident": incident_details
    }
    
    try:
        # Mocking the request for the script execution
        print(f"[SOAR] Sending payload to CSIRT: {json.dumps(payload, indent=2)}")
        # response = requests.post(webhook_url, json=payload, timeout=5)
        # response.raise_for_status()
        print("[SOAR] NIS2 Alert successfully routed to CSIRT.")
    except Exception as e:
        print(f"[SOAR] FAILED to route NIS2 Alert: {e}")

if __name__ == "__main__":
    mock_incident = {
        "type": "Unauthorized Access Attempt",
        "target": "Core Database",
        "source_ip": "192.168.1.100",
        "mitigation_applied": "IP Blocked via WAF"
    }
    trigger_nis2_alert(mock_incident)