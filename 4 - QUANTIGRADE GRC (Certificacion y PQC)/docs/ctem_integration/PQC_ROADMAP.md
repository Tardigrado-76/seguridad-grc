# Roadmap de Criptografía Post-Cuántica (PQC) en Quantigrade GCR

## 1. Contexto Regulatorio y Amenaza Q-Day

La transición hacia la criptografía resistente a la computación cuántica es un mandato explícito en:
- **ENS RD 311/2022**: Medida `[op.sec.3]` Criptografía y Guías CCN-STIC 800.
- **NIST Post-Quantum Cryptography Standardization (Agosto 2024)**:
  - **FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
  - **FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
  - **FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- **Directiva NIS2 (UE 2022/2555)**: Requisito de cifrado robusto a prueba de futuro (Agilidad Criptográfica).

---

## 2. Estrategia Híbrida Adoptada

Quantigrade GCR implementa una arquitectura de **doble capa criptográfica (Hybrid Schemes)** para garantizar compatibilidad retroactiva y protección simultánea contra algoritmos clásicos y cuánticos:

```
┌─────────────────────────────────────────────────────────────┐
│                      CABECERA JWT / TOKEN                   │
│   alg: "ES256+ML-DSA-65"  (Dual Signature Scheme)           │
├──────────────────────────────┬──────────────────────────────┤
│      FIRMA CLÁSICA           │        FIRMA CUÁNTICA        │
│   ECDSA P-256 (FIPS 186-5)   │      ML-DSA-65 (FIPS 204)    │
│  Resistencia Pre-Quantum     │      Resistencia Post-Quantum│
└──────────────────────────────┴──────────────────────────────┘
```

Ambas firmas deben ser validadas satisfactoriamente. Si cualquiera de las dos resulta truncada, alterada o falta en el token, el validador deniega el acceso inmediatamente (`Fail-Closed`).

---

## 3. Verificación de Resistencia mediante Fuzzing

El módulo de pruebas `core_mesh/tests/test_pqc_hybrid_fuzzing.py` somete al motor a escenarios adversarios continuos:
1. **Truncamiento de firma PQC**: Detección de pérdida de bytes en ML-DSA.
2. **Alteración bit a bit de firma clásica**: Detección de falsificación en la clave clásica.
3. **Modificación de payload en tránsito**: Invalidación de la atestación completa.
4. **Degradación de algoritmo**: Rechazo de tokens que omiten cualquiera de las dos firmas.

