# IT_COMPLIANCE_MANAGER

**Automated Audit & Technical Governance Engine for Enterprise MSP/SaaS Environments**

`IT_COMPLIANCE_MANAGER` is a Compliance-as-Code engine and CLI orchestrator designed to evaluate systems and codebases against European and International cybersecurity and regulatory frameworks:

- **DORA** (EU Regulation 2022/2554 - ICT Risk, Incident Notification, Third-Party Risk)
- **NIS2** (EU Directive 2022/2555 - Technical & Operational Cybersecurity Measures)
- **ENS Categoría Alta** (Real Decreto 311/2022 - Esquema Nacional de Seguridad)
- **RGPD / LOPDGDD** (EU Regulation 2016/679 - Art. 15 SAR, Art. 17 Erasure, Art. 32 TOMs)
- **EU AI Act** (EU Regulation 2024/1689 - Art. 9 Risk, Art. 14 Human Oversight, Art. 27 FRIA)
- **CRA** (EU Cyber Resilience Act - Art. 10 CycloneDX SBOM & Patch Management)
- **ISO/IEC 27001:2022** (Annex A Controls Mapping & Dynamic Gap Closer)
- **SOC 2** (AICPA Trust Services Criteria Mapping & Dynamic Certification)

---

## Architecture & Submodules

```
IT_COMPLIANCE_MANAGER/
├── orchestrator_cli.py               <-- Main CLI Orquestador Script
├── requirements.txt
├── .env.example
├── .gitignore
└── src/
    ├── core/                         <-- CLI Parser & Framework Orchestrator
    ├── evaluators/                   <-- Framework-specific Python Rule Engines & ISO/SOC2 Mapper
    ├── reporters/                    <-- Executive CISO Summary, Evidence Matrix & GDPR Reports (.pdf/.md)
    └── sealer/                       <-- SHA-256 Merkle Tree, SLSA v1.0 Level 3+ & Digital Signature
```

## CLI Usage

```bash
# Execute full compliance audit for a target directory
python orchestrator_cli.py --input C:/MyProject --framework ALL --company "CONVOTIS_Client_X" --output ./reports --format both

# Run specific frameworks (e.g. DORA & ENS_ALTO) with PDF report
python orchestrator_cli.py -i /var/www/app -f DORA ENS_ALTO -c "MyCompany" -o ./reports -fmt pdf
```

## Immutable Chain of Custody
Every audit execution automatically hashes all generated report artifacts, constructs a Merkle Tree, attaches an SLSA v1.0 Level 3+ provenance attestation, and seals the output into `CHAIN_OF_CUSTODY_MANIFEST.json`.
