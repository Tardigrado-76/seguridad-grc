# Plan Maestro Definitivo de Auditoría de Ciberseguridad y Cumplimiento Regulatorio
## Proyecto X — Documento de Trabajo del Auditor Principal

> **Versión:** 1.0 FINAL
> **Fecha de emisión:** 2026-07-26T15:46 CEST
> **Clasificación:** CONFIDENCIAL — USO INTERNO DEL EQUIPO AUDITOR
> **Directorio raíz Proyecto X:** `e:\PROYECTOS IA\AUDITORIAS\NORMATIVAS\`

---

## 1. Enfoque de Auditoría Regional y Sectorial

Como Auditor Principal operando en el eje tecnológico Sur/Este de España, la estrategia de inspección se calibra según la **superficie de ataque real**, las **obligaciones legales vinculantes** y el **perfil de amenaza** de cada nodo:

| Nodo Regional | Actores Clave | Perfil de Amenaza | Marcos Dominantes |
| :--- | :--- | :--- | :--- |
| **Alicante** (Distrito Digital + ELLIS) | Startups IA, scale-ups, ELLIS Alicante (IA Human-Centric) | Ciberdelincuencia oportunista → Espionaje industrial (ELLIS) | RGPD, OWASP, EU AI Act |
| **Valencia** (Puerto + Administración) | Autoridad Portuaria, Ayuntamientos, IT Gubernamental, Logística | Ransomware dirigido, sabotaje de infraestructuras críticas | ENS Alto, NIS2, LPIC, DORA |
| **Sevilla** (Hub Aeroespacial/Defensa) | Contratistas MoD, fabricantes de sistemas duales, satélites | APTs de Estado-Nación (Harvest Now, Decrypt Later) | FIPS 140-3, PQC, DORA TLPT, SLSA L3+ |

---

## 2. Tabla Definitiva — PERFIL 1: Empresa Nacional Privada (Nivel Bajo/Medio)

**Sector tipo:** Startup SaaS en Distrito Digital Alicante, consultora IT en Sevilla, desarrollo web en Valencia.
**Amenaza dominante:** Fuga de datos de clientes, incumplimiento RGPD, vulnerabilidades web comunes.
**Scripts asignados: 6** — Batería mínima obligatoria.

| Normativa | Orden | Script | Función Principal | Justificación de Auditoría | Archivos / Directorios Objetivo | Comando CLI |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **Supply Chain** | **01** | `generate_sbom.py` | Generación de SBOM de dependencias del proyecto. | **Fase 1 — Inventario.** Aunque no liciten con la Administración, conocer sus dependencias es el acto fundacional de la higiene de seguridad. Sin SBOM, no saben si usan `log4j` o `polyfill.io` comprometidos. | `requirements.txt`, `package.json`, `Pipfile.lock`, `go.mod`, `*.csproj`, lockfiles del proyecto. | `python "./NORMATIVAS/Supply Chain Security/generate_sbom.py" --output-dir ./reports` |
| **RGPD / LOPDGDD** | **02** | `rgpd_data_pseudonymizer.ps1` | Seudonimización determinista HMAC-SHA256 de BBDD Non-Prod. | **Fase 2 — Protección de Datos.** Almacenan datos de clientes españoles. La AEPD impone multas de hasta el 4% de facturación global si los datos reales se usan en entornos de desarrollo o testing sin seudonimizar (Art. 25 RGPD, Privacidad desde el Diseño). | Exportaciones CSV/JSON de bases de datos, dumps de MySQL/PostgreSQL, entornos de staging con datos de clientes. | `pwsh "./NORMATIVAS/RGPD - LOPDGDD/rgpd_data_pseudonymizer.ps1" -Mode Pseudonymize -OutputDir ./reports` |
| **OWASP Top 10** | **03** | `ast_scan.py` | Análisis estático de seguridad (SAST). | **Fase 2 — Hardening de Código.** La mayoría de brechas en pymes IT provienen de inyecciones SQL (A03:2025) y XSS. El SAST detecta estos patrones sin ejecutar código ni impactar producción. Es la prueba de diligencia debida más básica. | `*.py`, `*.js`, `*.ts`, `*.html`, `*.jsx` — Todo el código fuente de la aplicación del cliente. | `python "./NORMATIVAS/OWASP top 10/ast_scan.py" --output-dir ./reports` |
| **OWASP LLM** | **04** | `llm_prompt_guard.py` | Guardrail contra Prompt Injection (LLM01). | **Fase 3 — Seguridad IA.** Si la startup integra APIs de OpenAI, Anthropic o modelos locales, necesitan un guardia de prompts. Sin él, un atacante puede exfiltrar el system prompt con datos internos o hacer que el LLM ejecute acciones no autorizadas. | Prompts de entrada del usuario, system prompts almacenados, archivos de configuración de guardrails del chatbot. | `python "./NORMATIVAS/OWASP LLM/llm_prompt_guard.py" --output-dir ./reports` |
| **RGPD / LOPDGDD** | **05** | `sar_data_extractor.py` | Extracción automatizada de PII para SAR (Art. 15). | **Fase 4 — Operación.** Cuando un ciudadano ejerce su Derecho de Acceso (ARCO), la empresa tiene **30 días naturales** para entregar todos sus datos. Sin automatización, incumplen sistemáticamente el plazo legal. | Bases de datos de producción (usuarios, pedidos, logs), ficheros de perfil de cliente, registros de actividad con PII. | `python "./NORMATIVAS/RGPD - LOPDGDD/sar_data_extractor.py" --dry-run --output-dir ./reports` |
| **RGPD / LOPDGDD** | **06** | `rgpd_data_retention_purger.py` | Destrucción criptográfica (Derecho al Olvido Art. 17). | **Fase 4 — Purga.** Paso final e irreversible. Solo se ejecuta tras verificar que: (a) los backups existen, (b) el SAR se ha procesado y (c) la retención legal ha expirado. La destrucción criptográfica garantiza que ni siquiera un forense puede recuperar los datos. | Registros de usuarios en BBDD, ficheros con PII cuyo período de retención ha expirado, backups de datos personales obsoletos. | `python "./NORMATIVAS/RGPD - LOPDGDD/rgpd_data_retention_purger.py" --dry-run --output-dir ./reports` |

---

## 3. Tabla Definitiva — PERFIL 2: Proveedor del Sector Público / Infraestructuras (ENS Medio/Alto, NIS2)

**Sector tipo:** IT para la Autoridad Portuaria de Valencia, subcontrata del Ministerio de Defensa, proveedor de la Generalitat Valenciana/Junta de Andalucía.
**Amenaza dominante:** Ransomware dirigido, compromiso de cadena de suministro (tipo SolarWinds), sabotaje de infraestructuras críticas.
**Scripts asignados: 10** — Batería completa de conformidad para licitaciones públicas.

| Normativa | Orden | Script | Función Principal | Justificación de Auditoría | Archivos / Directorios Objetivo | Comando CLI |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **Supply Chain / NIS2** | **01** | `generate_sbom.py` | Generación de SBOM (CycloneDX/SPDX). | **Fase 1 — Inventario.** Los pliegos de la LCSP exigen cada vez más la entrega de un SBOM junto con el software desplegado. NIS2 Art. 21 lo convierte en obligación legal para "Entidades Importantes". | `requirements.txt`, `package.json`, `Pipfile.lock`, `go.mod`, todas las dependencias del sistema entregado. | `python "./NORMATIVAS/Supply Chain Security/generate_sbom.py" --output-dir ./reports` |
| **NIS2** | **02** | `cisa_kev_gate.py` | Gate de validación contra catálogo KEV. | **Fase 1 — Descubrimiento de Riesgo.** Con el SBOM generado, se cruzan las dependencias contra las CVEs activamente explotadas. Si el software del puerto contiene una KEV, la auditoría se detiene hasta su remediación. | SBOM generado en paso 01, catálogo CISA KEV (API/JSON local). | `python "./NORMATIVAS/Supply Chain Security/cisa_kev_gate.py" --output-dir ./reports` |
| **NIS2** | **03** | `trm_vendor_scanner.py` | Evaluación de riesgo de proveedores (TPRM). | **Fase 1 — Inventario de Terceros.** NIS2 Art. 21(2)(d): "seguridad de la cadena de suministro". Antes de conectar una subcontrata al sistema portuario, se escanean sus dominios (SSL, cabeceras, CVEs públicas). | Dominios y URLs de proveedores B2B, certificados SSL, cabeceras HTTP de seguridad, registros DNS. | `python "./NORMATIVAS/NIS2/trm_vendor_scanner.py" --dry-run --output-dir ./reports` |
| **ENS Nivel Alto** | **04** | `disa_stig_hardening.ps1` | Hardening del SO bajo DISA STIG. | **Fase 2 — Hardening.** ENS `op.exp.2` (Configuración de Seguridad) y `op.exp.3` (Gestión de la Configuración). Los servidores que alojan servicios públicos deben tener políticas de contraseñas, auditoría y servicios mínimos. | Registro de Windows, GPOs locales, servicios del SO, políticas de auditoría, `secpol.msc`. | `pwsh "./NORMATIVAS/ENS 1-3-5/disa_stig_hardening.ps1"` |
| **ENS Nivel Alto** | **05** | `tpm_fde_validator.ps1` | Validación de TPM 2.0 y cifrado FDE/BitLocker. | **Fase 2 — Cifrado en Reposo.** ENS `mp.si.2` (Cifrado de Soportes). Si los discos del servidor portuario no están cifrados con TPM, un robo físico expondría datos de operaciones marítimas clasificadas. | Módulo TPM 2.0 del hardware, estado de BitLocker de todos los volúmenes, claves de recuperación. | `pwsh "./NORMATIVAS/ENS 1-3-5/tpm_fde_validator.ps1" -OutputDir ./reports` |
| **ENS Nivel Alto** | **06** | `ens_fim_enforcer.ps1` | Monitorización de Integridad de Archivos (FIM). | **Fase 2 — Protección.** ENS `op.exp.5` (Gestión de Cambios). Establece la línea base SHA-256 de todos los binarios críticos. Cualquier modificación no autorizada (ransomware, rootkit) se detecta en tiempo real. | `C:\Windows\System32\`, binarios de aplicaciones críticas, archivos de configuración del sistema, DLLs. | `pwsh "./NORMATIVAS/ENS 1-3-5/ens_fim_enforcer.ps1" -Mode ScanAndEnforce -OutputDir ./reports` |
| **EU AI Act** | **07** | `ai_sec_guard.py` | Gateway interceptor de inferencia anómala y fugas PII. | **Fase 3 — Seguridad IA.** Si el puerto o la Generalitat usan IA predictiva (logística, chatbots ciudadanos), este gateway bloquea la exfiltración de datos sensibles hacia el proveedor del LLM. | Peticiones HTTP/API de inferencia, respuestas del modelo LLM, logs de sesión, payloads con PII. | `python "./NORMATIVAS/EU IA Act/ai_sec_guard.py" --output-dir ./reports` |
| **ENS / DORA** | **08** | `Bunker_secure_backup.py` | Respaldo inmutable cifrado en almacenamiento frío. | **Fase 4 — Resiliencia.** ENS `op.cont.1` (Análisis de Impacto) y DORA Art. 11 (Backup). Garantiza que el puerto o ayuntamiento se levanta tras un ransomware con backups que el atacante no puede cifrar. | Directorios de datos críticos del sistema gubernamental, BBDD de operaciones portuarias, configuraciones de red. | `python "./NORMATIVAS/ENS 1-3-5/Bunker_secure_backup.py" --dry-run --output-dir ./reports` |
| **DORA** | **09** | `dora_chaos_resilience_tester.py` | Motor de Chaos Engineering (TLPT). | **Fase 4 — Pruebas de Resiliencia.** DORA Art. 25 obliga a las "Entidades Financieras" y por extensión a las infraestructuras críticas a realizar pruebas de penetración guiadas por amenazas. Inyecta fallos reales para verificar que los SLA de continuidad se cumplen. | Servicios críticos del sistema, procesos del SO, conectividad de red, DNS, bases de datos réplica. | `python "./NORMATIVAS/DORA/dora_chaos_resilience_tester.py" --dry-run --output-dir ./reports` |
| **NIS2** | **10** | `23_nca_incident_reporter.py` | Reporte automatizado al CSIRT nacional. | **Fase 4 — Notificación Legal.** NIS2 Art. 23: notificación obligatoria al CCN-CERT o INCIBE en **24h** (alerta temprana) y **72h** (informe completo). Sin automatización, incumplir los plazos supone sanción administrativa directa. | Informes de incidentes generados, datos de clasificación, plantilla de reporte CSIRT, evidencias de los pasos 04-09. | `python "./NORMATIVAS/NIS2/23_nca_incident_reporter.py" --dry-run --output-dir ./reports` |

---

## 4. Tabla Definitiva — PERFIL 3: Multinacional Crítica (Aeroespacial, Defensa, IA Dual-Use, ELLIS)

**Sector tipo:** Contratista aeroespacial en Sevilla, fabricante de sistemas de armamento, ELLIS Alicante (IA de alto riesgo), gestión portuaria crítica (Valencia — sistema SCADA).
**Amenaza dominante:** APTs de Estado-Nación (Rusia, China), computación cuántica ofensiva, envenenamiento de modelos IA, ataques a la cadena de suministro de grado militar.
**Scripts asignados: 14** — Arsenal completo de grado militar + IA.

| Normativa | Orden | Script | Función Principal | Justificación de Auditoría | Archivos / Directorios Objetivo | Comando CLI |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| **PQC (FIPS)** | **01** | `11_collect-pqc-evidence.sh` | Recolección de evidencias de uso PQC en la infraestructura. | **Fase 1 — Inventario Cuántico.** Antes de migrar, Defensa necesita saber exactamente qué algoritmos vulnerables a Shor/Grover están incrustados en sistemas legacy (radares, comunicaciones, firmware embebido). Es el mapa de la superficie de ataque cuántica. | Binarios OpenSSL/LibreSSL, librerías `liboqs`/`libsodium`, configuraciones IPsec/IKEv2, firmware de dispositivos. | `bash "./NORMATIVAS/PQC FIPS 203-204-205/11_collect-pqc-evidence.sh"` |
| **Supply Chain** | **02** | `generate_sbom.py` | Generación de SBOM de la cadena de suministro completa. | **Fase 1 — Inventario de Componentes.** SLSA Nivel 3+ exige trazabilidad total de cada componente. En Defensa, un componente comprometido puede significar la exfiltración de telemetría de satélites o sistemas de armas. | `requirements.txt`, `package.json`, `Pipfile.lock`, `go.mod`, manifiestos de contenedores, firmware BOMs. | `python "./NORMATIVAS/Supply Chain Security/generate_sbom.py" --output-dir ./reports` |
| **Supply Chain / NIS2** | **03** | `cisa_kev_gate.py` | Gate de validación contra catálogo KEV. | **Fase 1 — Descubrimiento.** Con el SBOM generado, se cruzan dependencias contra CVEs activamente explotadas. En entornos clasificados, una sola KEV puede comprometer una red air-gapped completa. | SBOM del paso 02, catálogo CISA KEV (descarga offline para redes clasificadas). | `python "./NORMATIVAS/Supply Chain Security/cisa_kev_gate.py" --output-dir ./reports` |
| **PQC (FIPS 203/204)** | **04** | `pqc_crypto_agility_manager.py` | Orquestador híbrido de Agilidad Criptográfica (ML-KEM + ML-DSA). | **Fase 2 — Hardening Criptográfico.** Transición proactiva de túneles IPsec y comunicaciones satelitales/militares a ML-KEM (FIPS 203) y ML-DSA (FIPS 204). El orquestador permite cambiar de algoritmo sin recompilar aplicaciones. | Configuraciones de VPN/IPsec, almacén de algoritmos PQC, certificados del sistema, configuración de `liboqs`. | `python "./NORMATIVAS/PQC FIPS 203-204-205/pqc_crypto_agility_manager.py" --dry-run --output-dir ./reports` |
| **FIPS 140-3** | **05** | `fips_mode_enforcer.py` | Activación de modo FIPS en Kernel y runtime Python. | **Fase 2 — Hardening del Núcleo.** Requisito ineludible en contratos DoD/NATO y MoD España. Fuerza al sistema a denegar cualquier operación criptográfica no aprobada por NIST (deshabilita MD5, SHA-1, DES, RC4 de raíz). | Registro de Windows (`FIPS=1`), `hashlib` de Python, Crypto-API del kernel, `/proc/sys/crypto/fips_enabled`. | `python "./NORMATIVAS/FIPS 140-3 - 186-5 - 197-202/fips_mode_enforcer.py" --dry-run --output-dir ./reports` |
| **ENS Nivel Alto** | **06** | `ens_fim_enforcer.ps1` | Monitorización de Integridad de Archivos (FIM). | **Fase 2 — Protección.** ENS `op.exp.5`. En sistemas de Defensa, un binario alterado puede significar un implant de APT (tipo Stuxnet). El FIM detecta cualquier byte modificado en tiempo real contra la baseline SHA-256. | `C:\Windows\System32\`, binarios de sistemas de control, firmware, DLLs de aplicaciones clasificadas. | `pwsh "./NORMATIVAS/ENS 1-3-5/ens_fim_enforcer.ps1" -Mode ScanAndEnforce -OutputDir ./reports` |
| **EU AI Act** | **07** | `ai_model_provenance_signer.py` | Firma y atestación de procedencia de pesos de IA (Sigstore/Cosign). | **Fase 3 — Integridad de Modelos IA.** EU AI Act Art. 15 (Seguridad). En ELLIS y Defensa, si un adversario altera los pesos del modelo (Data Poisoning), la IA podría generar clasificaciones erróneas de objetivos o introducir sesgos deliberados. La firma bloquea la carga de cualquier modelo sin atestación válida. | Archivos de pesos `.safetensors`, `.pt`, `.onnx`, registro Sigstore/Cosign, manifiestos de modelos. | `python "./NORMATIVAS/EU IA Act/ai_model_provenance_signer.py" --dry-run --output-dir ./reports` |
| **EU AI Act** | **08** | `ai_compliance_auditor.py` | Escáner de sesgos, explicabilidad y registro de conformidad AI Act. | **Fase 3 — Auditoría de Conformidad IA.** EU AI Act Art. 14 (Supervisión Humana). Para ELLIS Alicante, la auditoría de sesgos es central a su misión de IA Human-Centric. Para Defensa, un modelo sesgado en reconocimiento de objetivos es un riesgo de víctimas civiles. | Datasets de entrenamiento, métricas de sesgo del modelo, logs de inferencia, configuración de hiperparámetros. | `python "./NORMATIVAS/EU IA Act/ai_compliance_auditor.py" --dry-run --output-dir ./reports` |
| **OWASP LLM** | **09** | `llm_autonomous_agent_jailbreak_honeypot.py` | Honeypot deceptivo para captura de jailbreaks y extracción de TTPs. | **Fase 3 — Seguridad Ofensiva (CTI).** Despliega un LLM "cebo" que simula vulnerabilidad a ataques DAN/Pliny. Captura los payloads de adversarios sofisticados que intentan comprometer los agentes IA tácticos, generando reglas WAF dinámicas para la defensa activa. | Prompts entrantes maliciosos, logs de sesión de atacantes, reglas de bloqueo IP del WAF corporativo. | `python "./NORMATIVAS/OWASP LLM/llm_autonomous_agent_jailbreak_honeypot.py" --dry-run --output-dir ./reports` |
| **EU AI Act** | **10** | `eu_ai_act_model_watermarker.py` | Inyección de marcas de agua esteganográficas Art. 50. | **Fase 3 — Protección IP.** EU AI Act Art. 50 obliga a identificar contenido generado por IA. En Defensa, las marcas de agua permiten rastrear fugas de inteligencia generada por IA hasta el nodo de origen exacto. | Salidas de texto generadas por LLMs, payloads de respuesta de API, imágenes sintéticas. | `python "./NORMATIVAS/EU IA Act/eu_ai_act_model_watermarker.py" --dry-run --output-dir ./reports` |
| **DORA / CRA** | **11** | `dora_chaos_resilience_tester.py` | Motor de Chaos Engineering con inyección TLPT. | **Fase 4 — Resiliencia Extrema.** DORA Art. 25 (TLPT). Simulaciones destructivas estructuradas que verifican que sistemas de comando, control o telemetría sobreviven a fallos catastróficos inyectados intencionalmente (caída de nodo, pérdida de red, corrupción de datos). | Servicios de telecomando, procesos críticos del sistema, conectividad de red interna, DNS, bases de datos réplica. | `python "./NORMATIVAS/DORA/dora_chaos_resilience_tester.py" --dry-run --output-dir ./reports` |
| **DORA** | **12** | `dora_automated_failover_drill.py` | Drill automatizado de failover DR midiendo RTO/RPO. | **Fase 4 — Disaster Recovery.** DORA Art. 11. Simula el fallo total del centro primario y mide si la conmutación al sitio de desastre cumple los SLA contractuales de Defensa (RTO < 4h, RPO < 1h para sistemas clasificados). | Región primaria y secundaria DR, bases de datos réplica, configuración DNS/BGP, scripts de failover. | `python "./NORMATIVAS/DORA/dora_automated_failover_drill.py" --dry-run --output-dir ./reports` |
| **PQC (FIPS 204)** | **13** | `fips_204_mldsa_git_commit_signer.py` | Firma PQ de commits Git con ML-DSA (Dilithium). | **Fase 4 — Integridad del Código Fuente.** El código que opera en sistemas de armas debe ser criptográficamente inmutable. ML-DSA protege los commits contra manipulación cuántica futura, blindando el repositorio más allá de la vida útil de RSA/ECDSA. | Commits de Git (`.git/`), tree hashes SHA-256, código fuente de aplicaciones clasificadas. | `python "./NORMATIVAS/PQC FIPS 203-204-205/fips_204_mldsa_git_commit_signer.py" --dry-run --output-dir ./reports` |
| **Supply Chain** | **14** | `slsa_provenance_signer.sh` | Atestación SLSA Provenance Nivel 3+. | **Fase 4 — Sello Final de Cadena.** Último paso del pipeline. Emite una prueba irrefutable y criptográfica de que el binario compilado para Defensa no ha sido manipulado durante el proceso de build. Es la defensa definitiva contra ataques tipo SolarWinds/XZ Utils. | Artefactos finales compilados (binarios, DLLs, imágenes de contenedor), logs de CI/CD, metadatos de build. | `bash "./NORMATIVAS/Supply Chain Security/slsa_provenance_signer.sh"` |

---

## 5. Cadena de Custodia de Evidencias Criptográficas

> [!CAUTION]
> Esta sección define el protocolo de preservación de evidencias que garantiza la **admisibilidad legal** de los informes ante reguladores (INCIBE, CCN-CERT, AEPD, ENISA) y tribunales.

### 5.1. Integridad Interna de Cada Informe

Cada script del Proyecto X implementa un **sellado criptográfico interno** en sus reportes:

| Propiedad | Implementación | Propósito Legal |
| :--- | :--- | :--- |
| **Timestamp ISO-8601** | `datetime.datetime.now(datetime.timezone.utc).isoformat()` | Prueba temporal irrefutable de cuándo se ejecutó el control. |
| **Hash SHA-256 del informe** | `hashlib.sha256(report_bytes).hexdigest()` | Prueba de que el contenido no ha sido alterado post-generación. |
| **Formato dual JSON + MD** | Escritura simultánea en ambos formatos. | JSON para ingesta automatizada (SIEM/SOAR); MD para lectura humana por el regulador. |

### 5.2. Consolidación: El Búnker de Evidencias

Tras completar la ejecución de la tabla correspondiente al perfil auditado, se ejecuta el sellado final:

```bash
# Paso 1: Backup cifrado e inmutable de todos los informes
python "./NORMATIVAS/ENS 1-3-5/Bunker_secure_backup.py" --target ./reports --output-dir ./audit_bunker

# Paso 2: Verificar inmutabilidad del lote
python "./NORMATIVAS/DORA/20_verify_log_immutability.py" --target ./audit_bunker --output-dir ./audit_bunker

# Paso 3: Firmar con atestación SLSA el paquete completo
bash "./NORMATIVAS/Supply Chain Security/slsa_provenance_signer.sh" --target ./audit_bunker
```

### 5.3. Manifiesto de Entrega al Regulador

El paquete final (`./audit_bunker/`) contendrá:

```
audit_bunker/
├── MANIFEST.sha256           ← Hash de cada archivo del lote
├── SLSA_PROVENANCE.json      ← Atestación de integridad del build
├── reports/
│   ├── SBOM-20260726.json
│   ├── RGPD-PSEUDONYMIZER-20260726.json
│   ├── ENS-FIM-20260726.json
│   ├── DORA-CHAOS-20260726.json
│   ├── PQC-EVIDENCE-20260726.json
│   ├── FIPS204-GIT-20260726.json
│   ├── ... (un archivo por cada script ejecutado)
│   └── AUDIT-FINAL-CONSOLIDATED.md
└── CHAIN_OF_CUSTODY.md       ← Este documento firmado
```

### 5.4. Protocolo de Entrega

| Paso | Acción | Destinatario |
| :---: | :--- | :--- |
| **1** | Entregar `audit_bunker.tar.gz.enc` cifrado con clave pública del regulador. | CCN-CERT / INCIBE / AEPD |
| **2** | Transmitir la clave simétrica AES-256 del sobre por canal seguro separado (presencial o HSM). | Responsable de Seguridad del cliente |
| **3** | El regulador verifica `MANIFEST.sha256` contra cada archivo para confirmar integridad. | Auditor del regulador |
| **4** | El regulador verifica `SLSA_PROVENANCE.json` para confirmar que los reportes no fueron manipulados post-auditoría. | Auditor del regulador |

> [!IMPORTANT]
> Este protocolo de doble canal (cifrado asimétrico + entrega presencial de clave) cumple con el ENS `mp.com.3` (Protección de la Información en Tránsito) y con el RGPD Art. 32 (Medidas Técnicas de Seguridad).

---

## 6. Resumen Ejecutivo Final

| Perfil | Scripts | Marcos Cubiertos | Nivel de Rigor | Región Primaria |
| :--- | :---: | :--- | :--- | :--- |
| **Perfil 1** — Empresa Privada | 6 | RGPD, OWASP, Supply Chain básico | Bajo-Medio | Distrito Digital Alicante, Sevilla |
| **Perfil 2** — Sector Público | 10 | ENS Alto, NIS2, DORA, EU AI Act, Supply Chain | Medio-Alto | Puerto de Valencia, Generalitat, Junta de Andalucía |
| **Perfil 3** — Defensa/IA Crítica | 14 | FIPS, PQC, DORA TLPT, EU AI Act, SLSA L3+, ENS Alto | CRÍTICO / Grado Militar | Hub Sevilla, ELLIS Alicante, Puerto Valencia (SCADA) |
