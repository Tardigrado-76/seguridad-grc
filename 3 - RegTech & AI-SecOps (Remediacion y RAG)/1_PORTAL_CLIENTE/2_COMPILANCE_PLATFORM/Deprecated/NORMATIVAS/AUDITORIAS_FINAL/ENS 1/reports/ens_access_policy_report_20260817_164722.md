# ENS RD 311/2022 Medida [op.acc.1] Control de Acceso Evidence Report

- **Timestamp (UTC):** `2026-08-17T16:47:22.764537+00:00`
- **Execution Mode:** `PRODUCTION`
- **Target Path:** `E:\PROYECTOS IA\AUDITORIAS\PRODUCTION-READY\NORMATIVAS\AUDITORIAS_FINAL\ENS 1`
- **Files Scanned:** `7`
- **Access Violations Detected:** `2`
- **ENS RD 311/2022 Compliant:** `False`
- **SHA-256 Checksum:** `8C396BA417F66192A22419F27C7FBF9EE5E94E00614E11D4FF144EBA6D2BDD89`

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
