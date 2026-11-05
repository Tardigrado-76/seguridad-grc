# ENS RD 311/2022 Medida [op.acc.1] Control de Acceso Evidence Report

- **Timestamp (UTC):** `2026-08-02T13:18:36.196141+00:00`
- **Execution Mode:** `PRODUCTION`
- **Target Path:** `E:\PROYECTOS IA\PORTFOLIO`
- **Files Scanned:** `41`
- **Access Violations Detected:** `1`
- **ENS RD 311/2022 Compliant:** `False`
- **SHA-256 Checksum:** `08EED3C40AA9247E06463865ACC1D87E93D5CB976A2C4CB928E5C1F8091EAF86`

## Access Policy Violations Details
```json
[
  {
    "file": "rag_ingestion_pipeline.py",
    "type": "HARDCODED_CREDS",
    "severity": "CRITICAL",
    "description": "Posible secreto o credencial hardcodeada en texto plano."
  }
]
```
