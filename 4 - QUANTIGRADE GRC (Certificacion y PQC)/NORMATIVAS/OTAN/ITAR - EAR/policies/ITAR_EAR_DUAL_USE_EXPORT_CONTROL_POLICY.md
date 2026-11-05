# POLÍTICA DE CONTROL DE EXPORTACIONES DE DEFENSA Y TECNOLOGÍAS DE DOBLE USO (ITAR / EAR / REGLAMENTO UE 2021/821)

## 1. Objeto y Alcance
Esta política regula la custodia, segregación, transferencia y licenciamiento de software, criptografía, datos técnicos y artículos clasificados bajo las normativas internacionales de control de exportaciones:
- **ITAR (International Traffic in Arms Regulations):** 22 CFR Parts 120-130 (Department of State / DDTC).
- **EAR (Export Administration Regulations):** 15 CFR Parts 730-774 (Department of Commerce / BIS).
- **Reglamento (UE) 2021/821:** Régimen de la Unión para el control de las exportaciones, el corretaje, la asistencia técnica, el tránsito y la transferencia de productos de doble uso.

## 2. Requisitos Operativos Mandatorios
1. **Segregación Lógica y Acceso Basado en Ciudadanía / Habilitación:** Queda terminantemente prohibido el acceso de personas extranjeras (*Foreign Persons*) no autorizadas a repositorios, trazas o datos técnicos de la lista USML.
2. **Clasificación ECCN y Matrices de Control de Doble Uso:** Todo algoritmo de cifrado, modelo de IA o componente software debe contar con su código ECCN (ej. 5D002, 4D001) y verificación bajo el Anexo I del Reglamento UE 2021/821.
3. **Cifrado FIPS 140-3 con Aislamiento Cero (*Zero Foreign Access*):** Las claves criptográficas deben custodiarse exclusivamente en territorio soberano de la UE/España sin delegación en proveedores cloud extraterritoriales ni acceso por entidades foráneas.
4. **Prevención de Re-exportación No Autorizada:** Auditoría automática en canalizaciones CI/CD para impedir la distribución no licenciada de artefactos binarios controlados.
