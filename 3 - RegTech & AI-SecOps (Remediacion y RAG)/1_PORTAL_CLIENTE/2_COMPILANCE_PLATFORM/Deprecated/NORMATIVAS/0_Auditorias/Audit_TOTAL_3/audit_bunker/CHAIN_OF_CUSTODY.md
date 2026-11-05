# ACTA OFICIAL DE CUMPLIMIENTO ENS / NIS2 Y CADENA DE CUSTODIA (PERFIL 2)
**Perfil:** Perfil 2 - Sector Público / ENS Alto / NIS2 / Puertos (PERFIL-2)
**Modo de Ejecución:** PRODUCCIÓN REAL
**Timestamp Criptográfico UTC:** `2026-07-28T16:49:51.268156+00:00`
**Operador Responsable:** `Tardigrado`
**Host / Sistema Auditor:** `N16 (Windows 11)`

---

## 1. CUMPLIMIENTO REGULATORIO Y LEGAL
- **Protección de la Información en Tránsito:** ENS RD 311/2022 [mp.com.3]
- **Notificación de Incidentes 24h:** NIS2 Directiva (UE) 2022/2555 Art. 23 / CCN-CERT / INCIBE
- **Inmutabilidad y Trazabilidad:** SLSA v1.0 Level 3+ Provenance

## 2. MATRIZ DE CORRESPONDENCIA Y CUMPLIMIENTO
| Fase | Módulo Técnico | Estado | Mapeo Normativo |
| :---: | :--- | :---: | :--- |
| 01 | Evaluación de Riesgos Terceros (SLSA L3+) | **SKIPPED** | CRA Art. 10 (Seguridad en Cadena de Suministro) | SLSA Level 3+ |
| 02 | Bloqueo Exploits Activos (CISA KEV Gate) | **SKIPPED** | NIS2 Art. 21(2)(e) (Gestión de Vulnerabilidades) | CISA KEV Catalog |
| 03 | Auditoría MFA y Cifrado (Art. 21) | **SKIPPED** | NIS2 Art. 21(2)(g) (MFA y Cifrado de Comunicaciones) | ENS [op.acc.4] |
| 04 | Control de Acceso ENS [op.acc.1] | **COMPLETED** | ENS RD 311/2022 [op.acc.1] (Control de Acceso) | NIS2 Art. 21(2)(i) |
| 05 | Cumplimiento Cloud EUCS | **COMPLETED** | ENISA EUCS (Esquema Europeo Certificación Cloud - Niveles Medio/Alto) |
| 06 | Reporte a Autoridades (CCN-CERT/INCIBE) | **SKIPPED** | NIS2 Art. 23 (Notificación Temprana 24h Incidentes a CCN-CERT / INCIBE) |
| 07 | Monitoreo Integridad de Archivos (FIM) | **COMPLETED** | ENS RD 311/2022 [op.exp.8] (Monitoreo Integridad FIM) | NIS2 Art. 21 |
| 08 | Agregador VEX Vulnerabilidades | **FAILED** | NIS2 Art. 21(2)(e) (VEX Aggregator) | CRA (Vulnerabilidades Cadena Suministro) |
| 09 | Auditoría Riesgos Proveedores IT (DORA/NIS2) | **COMPLETED** | DORA Art. 28-30 (Riesgo Proveedores IT) | NIS2 Art. 21(2)(d) |
| 10 | Transparencia y Marcas de Agua IA | **FAILED** | EU AI Act Art. 50 (Transparencia y Marcas de Agua IA Sector Público) |

## 3. MANIFIESTO DE ARTEFACTOS Y SELLADO CRIPTOGRÁFICO (SHA-256)
| Archivo de Evidencia | SHA-256 Digest |
| :--- | :--- |
| `reports/AUDITORIA_CONSOLIDADA_PERFIL2_DEMO.pdf` | `2fbe2239516a78f971e22aeada6bd3bb5264d3d8df4ff6cbaeab3480c0c2d399` |
| `reports/AUDITORIA_CONSOLIDADA_SUMMARY.md` | `30ab92068ee9a119007164f74be0ab16d42548aec8bf56d9a0320f23eb345043` |
| `reports/dora_ict_third_party_risk_report_20260728_163743.json` | `1729c0526469ce9d95c598cdd5d2c3bc42403884ef795cf2d2a98342ae7a3c13` |
| `reports/dora_ict_third_party_risk_report_20260728_163743.md` | `473da6b921caa468834132438970e3a7ce2c54aa60833158f00d8f0214ed06e5` |
| `reports/dora_ict_third_party_risk_report_20260728_164950.json` | `fd04ddfcbdab39c726ab82772fb20a635de2c14832379cd3bf7f95e37142ac69` |
| `reports/dora_ict_third_party_risk_report_20260728_164950.md` | `acbc1de207eb540533491b360b8929991f5fe5bd72cbe775a923e851a2a6a1fb` |
| `reports/enisa_eucs_cloud_report_20260728_163742.json` | `75468fd4ed74920a9fd4a2b26bbf604551c56cd50023a3e2c7a906f67475ef17` |
| `reports/enisa_eucs_cloud_report_20260728_163742.md` | `050ff9da30220c0ea6d8cbc83665c8908cadab3da555f8a9eaf6efa0fcb4636b` |
| `reports/enisa_eucs_cloud_report_20260728_164949.json` | `3f6929d17482acc0618caefec57f64127f82879eafef44e35cab80c5c5d7aac9` |
| `reports/enisa_eucs_cloud_report_20260728_164949.md` | `42412514c434aa698eb2faa48e04217e1414a1a0f76feebbd624926eccd3939d` |
| `reports/ens_access_policy_report_20260728_163742.json` | `fb5dc1a2f2686aeaf00e06529e87b64a7a62a93d56a54fac56c7402339ee25b7` |
| `reports/ens_access_policy_report_20260728_163742.md` | `86882e727a72f1323bcce0bf8336ada1f7f8d4c1f68313d3bdd853ec3a3daf3e` |
| `reports/ens_access_policy_report_20260728_164949.json` | `6aef4eeb5140cb37cbc66ba41e808418aab63e0da872b17b21fa600848c22112` |
| `reports/ens_access_policy_report_20260728_164949.md` | `75d7c0da0a801e5b75da25344db1b0c9037716caea39e71dc40132dc3483b3b6` |
| `reports/NIS2_INCIDENT_NOTIFICATION_24H.md` | `040754bcfb9111f1be41cb99bfc512399ef039fab7ea69acf3801ca69d4626c6` |

## 4. PROTOCOLO DE ENTREGA AL REGULADOR (CCN-CERT / INCIBE / AEPD)
1. **Paquete Cifrado:** Copia inmutable `audit_bunker.tar.gz.enc` cifrada mediante AES-256-GCM.
2. **Entrega de Claves:** Canal seguro fuera de banda (presencial / HSM).
3. **Verificación de Inmutabilidad:** El regulador contrasta `MANIFEST.sha256` y `SLSA_PROVENANCE.json`.
