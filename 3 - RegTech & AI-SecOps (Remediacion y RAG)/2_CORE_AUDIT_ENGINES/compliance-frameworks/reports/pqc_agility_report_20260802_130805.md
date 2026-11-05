# Post-Quantum Crypto-Agility Audit Report (FIPS 203/204/205)

- **Timestamp (UTC):** 2026-08-02T13:08:05.502028+00:00
- **Target Directory:** `"E:\PROYECTOS IA\TODO BUNKER_OS"`
- **Scan Mode:** `RotateHybridSimulated`
- **Evidence SHA-256:** `f4f84e0d8b781a9ba2261b31ec1d362bc826a36cce5a43f614e0c4053ba5d0f7`

## Readiness Summary
- **Total Assets Scanned:** `3`
- **Vulnerable Legacy Keys:** `2`
- **Quantum Tolerant Keys:** `0`
- **PQC-Ready Keys:** `1`

## Asset Classification Breakdown
```json
[
  {
    "file": "\"E:\\PROYECTOS IA\\TODO BUNKER_OS\"\\dev_cert.key",
    "algorithm": "RSA-2048",
    "classification": "Vulnerable_Legacy",
    "recommended_pqc_replacement": "ML-KEM-1024 (FIPS 203)"
  },
  {
    "file": "\"E:\\PROYECTOS IA\\TODO BUNKER_OS\"\\mtls_ca.crt",
    "algorithm": "ECC-P256",
    "classification": "Vulnerable_Legacy",
    "recommended_pqc_replacement": "ML-DSA-87 (FIPS 204)"
  },
  {
    "file": "\"E:\\PROYECTOS IA\\TODO BUNKER_OS\"\\pqc_experiment.pem",
    "algorithm": "ML-KEM (FIPS 203)",
    "classification": "PQC_Ready",
    "recommended_pqc_replacement": "Already PQC Compliant"
  }
]
```
