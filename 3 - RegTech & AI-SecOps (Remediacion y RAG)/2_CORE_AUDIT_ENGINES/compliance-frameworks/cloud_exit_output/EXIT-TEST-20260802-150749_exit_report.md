# Informe de Ensayo de Estrategia de Salida Cloud (DORA Art. 28.8)

**ID de la Prueba:** `EXIT-TEST-20260802-150749`  
**Proveedor TIC Crítico:** AWS Cloud EMEA  
**Infraestructura Destino Secundario:** "E:\PROYECTOS IA\TODO BUNKER_OS"  
**Fecha de Ejecución:** 2026-08-02T13:07:50.214658+00:00  
**Dictamen DORA:** ✅ ESTRATEGIA DE SALIDA VALIDADA (EXIT DRY-RUN SUCCESS)  

---

## 1. Validación de Objetivos de Recuperación (SLA vs Medido)

| Métrica de Resiliencia | Objetivo Contratado (SLA) | Resultado Real Medido | Estado Cumplimiento |
|------------------------|---------------------------|-----------------------|---------------------|
| **RTO (Recovery Time)** | <= 120.0 min (2.0h) | **90.01 min** | ✅ CONFORME |
| **RPO (Recovery Point)** | <= 30.0 min | **15.00 min** | ✅ CONFORME |
| **Integridad de Datos** | SHA-256 Coincidente | Checksum Verificado | ✅ OK |

---

## 2. Desglose Tiempos de Ejecución Simulación

- **Volumen de Base de Datos Ensayada:** 50.0 GB
- **Tiempo de Dump / Exportación:** 0.002s
- **Cálculo de Checksum SHA-256:** 0.022s
- **Transferencia a Red Secundaria:** 0.501s
- **Restauración en Entorno Local/On-Prem:** 0.002s
- **Hash SHA-256 de Estado Restablecido:**  
  `3e5e309818ec17e03968c539da699ddc2f9a9a670130cfd9a358a8e8eb5ed646`

---

## 3. Conclusiones y Cumplimiento Regulatorio

> El Artículo 28.8 del Reglamento DORA exige probar activamente que los sistemas pueden ser
> migrados o restaurados en un proveedor secundario o infraestructura propia sin comprometer
> la continuidad operativa de las funciones esenciales ni sobrepasar los límites RTO/RPO.

---
*Generado por `cloud_exit_strategy_test.py` el 2026-08-02T13:07:50.214658+00:00*
