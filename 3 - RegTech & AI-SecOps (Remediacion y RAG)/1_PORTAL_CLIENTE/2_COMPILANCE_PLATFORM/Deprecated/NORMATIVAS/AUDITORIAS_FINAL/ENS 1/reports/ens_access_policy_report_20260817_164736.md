# ENS RD 311/2022 Medida [op.acc.1] Control de Acceso Evidence Report

- **Timestamp (UTC):** `2026-08-17T16:47:36.030782+00:00`
- **Execution Mode:** `PRODUCTION`
- **Target Path:** `E:\PROYECTOS IA\AUDITORIAS\PRODUCTION-READY\NORMATIVAS\AUDITORIAS_FINAL\ENS 1`
- **Files Scanned:** `7`
- **Access Violations Detected:** `2`
- **ENS RD 311/2022 Compliant:** `False`
- **SHA-256 Checksum:** `58DC807209DBABACDE8527CDC7B058E0A3E6B21FB42F68454D6303436D8439C3`

## Access Policy Violations Details
```json
[
  {
    "file": "ens_access_policy_auditor.py",
    "type": "HARDCODED_CREDS",
    "severity": "CRITICAL",
    "description": "Posible secreto o credencial hardcodeada en texto plano."
  },
  {
    "file": "ens_access_policy_auditor.py",
    "type": "WORLD_WRITABLE",
    "severity": "HIGH",
    "description": "Asignaci\u00f3n insegura de permisos globales chmod 777."
  }
]
```
