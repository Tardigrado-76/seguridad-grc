import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
"""
verify_log_immutability.py - Verificador de Integridad e Inmutabilidad de Logs de Auditoría (DORA Art. 10).

Cumplimiento Regulatorio:
-------------------------
- DORA (Reglamento UE 2022/2554): Artículo 10 (Sistemas de Detección, Registro e Inmutabilidad de Logs).
- Exigencia: Los registros de auditoría y eventos de seguridad deben ser trazables, inalterables
  y contar con mecanismos de verificación criptográfica (Merkle Tree / Encadenamiento SHA-256).

Descripción:
------------
Verifica la integridad de los archivos de log escaneando los registros, calculando el árbol
de Merkle / cadena de hashes SHA-256 y detectando cualquier alteración, borrado o inserción no autorizada.

Uso:
----
  python verify_log_immutability.py --create-sample-log ./sample_immutable.log
  python verify_log_immutability.py --log-file ./sample_immutable.log --output-dir ./log_integrity_reports
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DORA_Log_Verifier")


@dataclass
class LogEntryValidation:
    """Resultado de la verificación de una entrada de log individual."""

    line_number: int
    raw_content: str
    entry_hash: str
    expected_previous_hash: str
    calculated_previous_hash: str
    is_valid: bool
    error_detail: Optional[str] = None


@dataclass
class MerkleTreeResult:
    """Resultado de la construcción del Árbol de Merkle."""

    root_hash: str
    total_leafs: int
    tree_depth: int
    leaf_hashes: List[str]


@dataclass
class LogIntegrityReport:
    """Reporte completo de verificación de inmutabilidad de logs."""

    log_file_path: str
    timestamp: str
    total_lines_scanned: int
    valid_lines_count: int
    tampered_lines_count: int
    is_integrity_intact: bool
    merkle_root_hash: str
    chain_broken_at_line: Optional[int]
    tampered_entries: List[Dict[str, Any]]
    dora_compliance_status: str


class MerkleTreeBuilder:
    """Calculador de Árbol de Merkle para verificación de integridades en lote."""

    @staticmethod
    def compute_sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @classmethod
    def build_merkle_tree(cls, hashes: List[str]) -> MerkleTreeResult:
        if not hashes:
            empty_root = cls.compute_sha256("")
            return MerkleTreeResult(root_hash=empty_root, total_leafs=0, tree_depth=0, leaf_hashes=[])

        current_level = list(hashes)
        depth = 0

        while len(current_level) > 1:
            depth += 1
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = cls.compute_sha256(left + right)
                next_level.append(combined)
            current_level = next_level

        return MerkleTreeResult(
            root_hash=current_level[0],
            total_leafs=len(hashes),
            tree_depth=depth,
            leaf_hashes=hashes,
        )


class DORALogImmutabilityVerifier:
    """Verificador de registros inmutables encadenados por hash conforme a DORA Art. 10."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, log_path: Path):
        self.log_path = log_path

    @classmethod
    def create_chained_log_file(cls, target_path: Path, num_entries: int = 10) -> None:
        """Crea un archivo de log de prueba sintético con encadenamiento SHA-256 inmutable."""
        target_path.parent.mkdir(parents=True, exist_ok=True)
        prev_hash = cls.GENESIS_HASH

        sample_events = [
            "USER_LOGIN_SUCCESS user=admin ip=192.168.1.50 mfa=ENABLED",
            "CONFIG_CHANGE component=WAF policy=BLOCK_SQLI action=UPDATE",
            "BACKUP_COMPLETED target=DB_PRIMARY size=45GB duration=12m",
            "ALERT_TRIGGERED rule=LARGE_DATA_EXPORT threshold=EXCEEDED",
            "IAM_ROLE_ASSIGNED user=jdoe role=SecOpsManager",
            "KEY_ROTATION status=SUCCESS key_id=KMS-EU-9921",
            "API_CALL endpoint=/v1/transfers status=200 latency=45ms",
            "FIREWALL_RULE_ADDED src=10.0.4.0/24 dst=8.8.8.8 action=ALLOW",
            "SESSION_TERMINATED user=admin reason=TIMEOUT",
            "AUDIT_CHECKPOINT status=OK merkle_sync=TRUE",
        ]

        with open(target_path, "w", encoding="utf-8") as f:
            for i in range(num_entries):
                timestamp = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=num_entries - i)).isoformat()
                payload = sample_events[i % len(sample_events)]
                entry_data_to_hash = f"{timestamp}|{payload}|{prev_hash}"
                current_hash = hashlib.sha256(entry_data_to_hash.encode("utf-8")).hexdigest()
                
                # Formato del log encadenado: TIMESTAMP | PAYLOAD | PREV_HASH | CURRENT_HASH
                log_line = f"{timestamp} | {payload} | {prev_hash} | {current_hash}\n"
                f.write(log_line)
                prev_hash = current_hash

        logger.info(f"Archivo de log inmutable sintético generado correctamente en: {target_path}")

    def verify_integrity(self) -> LogIntegrityReport:
        """Audita la cadena de hashes y construye el árbol Merkle del archivo de log."""
        if not self.log_path.exists():
            raise FileNotFoundError(f"No se encontró el archivo de log: {self.log_path}")

        lines_scanned = 0
        valid_count = 0
        tampered_count = 0
        expected_prev_hash = self.GENESIS_HASH
        first_broken_line: Optional[int] = None
        tampered_list: List[LogEntryValidation] = []
        leaf_hashes: List[str] = []

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                line_str = line.strip()
                if not line_str:
                    continue

                lines_scanned += 1
                parts = [p.strip() for p in line_str.split("|")]

                if len(parts) < 4:
                    tampered_count += 1
                    if first_broken_line is None:
                        first_broken_line = line_idx
                    tampered_list.append(
                        LogEntryValidation(
                            line_number=line_idx,
                            raw_content=line_str,
                            entry_hash="",
                            expected_previous_hash=expected_prev_hash,
                            calculated_previous_hash="FORMAT_ERROR",
                            is_valid=False,
                            error_detail="Formato de línea no válido (Faltan delimitadores de cadena '|').",
                        )
                    )
                    continue

                timestamp, payload, prev_hash_in_log, current_hash_in_log = parts[0], parts[1], parts[2], parts[3]

                # 1. Validar encadenamiento con la línea anterior
                chain_ok = (prev_hash_in_log == expected_prev_hash)

                # 2. Recalcular el hash del contenido actual
                recomputed_data = f"{timestamp}|{payload}|{prev_hash_in_log}"
                recomputed_hash = hashlib.sha256(recomputed_data.encode("utf-8")).hexdigest()
                hash_ok = (recomputed_hash == current_hash_in_log)

                is_line_valid = chain_ok and hash_ok

                if is_line_valid:
                    valid_count += 1
                    leaf_hashes.append(current_hash_in_log)
                    expected_prev_hash = current_hash_in_log
                else:
                    tampered_count += 1
                    if first_broken_line is None:
                        first_broken_line = line_idx
                    
                    err_msg = []
                    if not chain_ok:
                        err_msg.append(f"Cadena rota (Hash anterior esperado: {expected_prev_hash[:12]}..., leido: {prev_hash_in_log[:12]}...)")
                    if not hash_ok:
                        err_msg.append(f"Falsificación de contenido (Hash recalculado: {recomputed_hash[:12]}..., leido: {current_hash_in_log[:12]}...)")

                    tampered_list.append(
                        LogEntryValidation(
                            line_number=line_idx,
                            raw_content=line_str,
                            entry_hash=current_hash_in_log,
                            expected_previous_hash=expected_prev_hash,
                            calculated_previous_hash=prev_hash_in_log,
                            is_valid=False,
                            error_detail="; ".join(err_msg),
                        )
                    )
                    # Actualizar para continuar escaneando si es posible
                    expected_prev_hash = current_hash_in_log

        merkle_res = MerkleTreeBuilder.build_merkle_tree(leaf_hashes)
        is_intact = (tampered_count == 0) and (lines_scanned > 0)
        compliance = "CONFORME_DORA_ART10" if is_intact else "NO_CONFORME_MODIFICACION_DETECTADA"

        return LogIntegrityReport(
            log_file_path=str(self.log_path.resolve()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            total_lines_scanned=lines_scanned,
            valid_lines_count=valid_count,
            tampered_lines_count=tampered_count,
            is_integrity_intact=is_intact,
            merkle_root_hash=merkle_res.root_hash,
            chain_broken_at_line=first_broken_line,
            tampered_entries=[asdict(t) for t in tampered_list],
            dora_compliance_status=compliance,
        )

    def export_json(self, report: LogIntegrityReport, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info(f"Informe de Inmutabilidad de Log JSON exportado en: {output_path}")

    def export_markdown(self, report: LogIntegrityReport, output_path: Path) -> None:
        status_badge = "✅ INTEGRIDAD INMUTABLE VERIFICADA" if report.is_integrity_intact else "🚨 ALTERACIÓN / MANIPULACIÓN DETECTADA"
        
        md_content = f"""# Auditoría de Inmutabilidad e Integridad de Logs (DORA Art. 10)

**Archivo Escaneado:** `{report.log_file_path}`  
**Fecha de Verificación:** {report.timestamp}  
**Estado de Integridad:** {status_badge}  
**Resultado DORA Art. 10:** `{report.dora_compliance_status}`  

---

## 1. Métricas del Análisis Criptográfico SHA-256 / Merkle Tree

- **Total de Registros Escaneados:** {report.total_lines_scanned}
- **Registros Válidos / No Manipulados:** {report.valid_lines_count}
- **Registros Alterados o Desalineados:** {report.tampered_lines_count}
- **Raíz del Árbol de Merkle (Merkle Root Hash):**  
  `{report.merkle_root_hash}`
- **Línea de Primera Ruptura de Cadena:** `{report.chain_broken_at_line if report.chain_broken_at_line else "N/A"}`

---

## 2. Hallazgos y Alteraciones Detectadas

"""
        if report.is_integrity_intact:
            md_content += "✅ **No se detectaron alteraciones.** Todos los hashes concuerdan secuencialmente y la cadena de bloques es ininterrumpida.\n"
        else:
            md_content += "| Línea | Error y Detalle del Hallazgo | Hash Esperado / Leído |\n"
            md_content += "|-------|------------------------------|------------------------|\n"
            for t in report.tampered_entries:
                md_content += f"| `{t['line_number']}` | {t['error_detail']} | `{t['expected_previous_hash'][:16]}...` |\n"

        md_content += f"""

---

## 3. Conformidad Regulatoria (DORA Art. 10)

> El Artículo 10 de DORA exige que las entidades financieras dispongan de registros inmutables,
> protegidos contra modificaciones retroactivas o supresiones no autorizadas.
> La raíz de Merkle generada (`{report.merkle_root_hash[:16]}...`) sirve como evidencia
> ante la auditoría interna y las Autoridades Competentes.

---
*Verificado por `verify_log_immutability.py` el {report.timestamp}*
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        logger.info(f"Informe de Inmutabilidad Markdown exportado en: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verificador de Inmutabilidad e Integridad de Logs de Auditoría (DORA Art. 10)."
    )
    parser.add_argument("--log-file", type=Path, help="Ruta al archivo de log a auditar.")
    parser.add_argument("--create-sample-log", type=Path, help="Genera un archivo de log inmutable de prueba en la ruta especificada.")
    parser.add_argument("--output-dir", type=Path, default=Path("./log_verification_output"), help="Directorio para guardar reportes.")

    args = parser.parse_args()

    if args.create_sample_log:
        DORALogImmutabilityVerifier.create_chained_log_file(args.create_sample_log)
        if not args.log_file:
            args.log_file = args.create_sample_log

    if not args.log_file:
        logger.error("Debe proporcionar --log-file <fichero.log> o --create-sample-log <fichero.log>.")
        parser.print_help()
        sys.exit(2)

    try:
        verifier = DORALogImmutabilityVerifier(args.log_file)
        report = verifier.verify_integrity()

        out_json = args.output_dir / f"{args.log_file.stem}_integrity.json"
        out_md = args.output_dir / f"{args.log_file.stem}_integrity.md"

        verifier.export_json(report, out_json)
        verifier.export_markdown(report, out_md)

        if report.is_integrity_intact:
            logger.info("Verificación exitosa: El archivo de log es totalmente inmutable y conforme a DORA Art. 10.")
            sys.exit(0)
        else:
            logger.warning("ALERTA DE SEGURIDAD: Se detectaron manipulaciones o ruptura de cadena en los registros.")
            sys.exit(1)

    except Exception as e:
        logger.critical(f"Error al verificar la inmutabilidad del log: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
