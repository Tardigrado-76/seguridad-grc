#!/usr/bin/env python3
"""bunker_secure_backup.py — Motor de Copias de Seguridad Encriptadas de BunkerOS.
=============================================================================
Cumplimiento: NIS2 Art. 21 (Resiliencia Operativa), ENS Categoría Alta,
NIST 800-53 (CP-9 Information System Backup), NIST 800-88 (Sanitización de Datos).

Realiza copias de seguridad calientes de las bases de datos de auditorías e incidentes
de SQLite, las cifra mediante AES-256-GCM utilizando la clave maestra $BUNKER_MASTER_KEY
y sanitiza los archivos temporales de forma segura.
"""

import argparse
import asyncio
import contextlib
import datetime
import hashlib
import logging
import os
import sqlite3
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Agregar directorio raíz al path para importar el logger de auditoría
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
except ImportError:
    pass

try:
    from src.bunker_logger import initialize_logger, log_auditoria
    initialize_logger()
except ImportError:
    # Fallback si se ejecuta de forma independiente
    def log_auditoria(user, action, message) -> None:
        pass
    def initialize_logger() -> None:
        pass

# Configurar logging normal a stdout
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BunkerBackup")


def derive_encryption_key(master_key: str) -> bytes:
    """Deriva una clave de 32 bytes fuerte utilizando PBKDF2
    con una sal única para el contexto de copias de seguridad.
    """
    salt = b"bunker_backup_encryption_salt_fixed"
    iterations = 100_000
    return hashlib.pbkdf2_hmac("sha256", master_key.encode("utf-8"), salt, iterations)


def secure_delete(file_path: str) -> None:
    """Sanitiza un archivo antes de eliminarlo según NIST 800-88 (single-pass overwrite)."""
    if not os.path.exists(file_path):
        return
    try:
        file_size = os.path.getsize(file_path)
        # Sobrescribir con datos pseudoaleatorios
        with open(file_path, "wb") as f:
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
        os.remove(file_path)
        logger.debug(f"[+] Archivo temporal sanitizado según NIST 800-88: {file_path}")
    except OSError as e:
        logger.warning(f"[!] Error al sanitizar {file_path}: {e}. Intentando borrado simple.")
        with contextlib.suppress(OSError):
            os.remove(file_path)


def backup_database(db_path: str, backup_dir: str, derived_key: bytes) -> str:
    """Realiza una copia en caliente de la base de datos y la cifra."""
    if not os.path.exists(db_path):
        msg = f"La base de datos no existe en: {db_path}"
        raise FileNotFoundError(msg)

    os.makedirs(backup_dir, exist_ok=True)
    db_name = os.path.basename(db_path)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_backup_path = os.path.join(backup_dir, f"temp_{db_name}.bak")
    encrypted_backup_path = os.path.join(backup_dir, f"{db_name}_backup_{timestamp}.enc")

    # 1. Copia en caliente usando la API nativa de copia de seguridad de SQLite (consistencia)
    logger.info(f"[*] Iniciando copia de seguridad en caliente de {db_name}...")
    try:
        src_conn = sqlite3.connect(db_path)
        dst_conn = sqlite3.connect(temp_backup_path)
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()
    except sqlite3.Error as e:
        if os.path.exists(temp_backup_path):
            os.remove(temp_backup_path)
        msg = f"Error al realizar copia en caliente de SQLite: {e}"
        raise RuntimeError(msg)

    # 2. Cifrar la base de datos copiada con AES-256-GCM
    logger.info("[*] Cifrando copia de seguridad con AES-256-GCM...")
    try:
        with open(temp_backup_path, "rb") as f:
            plain_data = f.read()

        # Generar vector de inicialización de 12 bytes
        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, plain_data, None)

        # Escribir nonce + datos cifrados en el destino final
        with open(encrypted_backup_path, "wb") as f:
            f.write(nonce + ciphertext)

        logger.info(f"[+] Copia de seguridad encriptada guardada en: {encrypted_backup_path}")
        asyncio.run(log_auditoria("SYSTEM", "BACKUP_SUCCESS", f"Backup cifrado creado para {db_name} -> {encrypted_backup_path}"))
        return encrypted_backup_path

    except (OSError, ValueError, TypeError, RuntimeError, InvalidTag) as e:
        asyncio.run(log_auditoria("SYSTEM", "BACKUP_FAIL", f"Error al cifrar backup para {db_name}: {e!s}"))
        msg = f"Error al cifrar el archivo de backup: {e}"
        raise RuntimeError(msg)
    finally:
        # 3. Sanitizar archivo temporal sin cifrar
        secure_delete(temp_backup_path)


def restore_database(backup_path: str, target_db_dir: str, derived_key: bytes) -> str:
    """Descifra un backup e intenta restaurarlo en la base de datos de destino."""
    if not os.path.exists(backup_path):
        msg = f"El archivo de backup no existe en: {backup_path}"
        raise FileNotFoundError(msg)

    # Extraer el nombre de la base de datos
    # Formato esperado: <db_name>_backup_<timestamp>.enc
    filename = os.path.basename(backup_path)
    if "_backup_" not in filename or not filename.endswith(".enc"):
        msg = f"Formato de nombre de backup inválido: {filename}"
        raise ValueError(msg)

    parts = filename.split("_backup_")
    db_name = parts[0]

    os.makedirs(target_db_dir, exist_ok=True)
    target_path = os.path.join(target_db_dir, db_name)
    temp_decrypted_path = os.path.join(target_db_dir, f"temp_restore_{db_name}")

    logger.info(f"[*] Descifrando copia de seguridad {filename}...")
    try:
        with open(backup_path, "rb") as f:
            encrypted_data = f.read()

        if len(encrypted_data) < 12:
            msg = "El archivo de backup está corrupto (demasiado corto)."
            raise ValueError(msg)

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        aesgcm = AESGCM(derived_key)
        plain_data = aesgcm.decrypt(nonce, ciphertext, None)

        # Guardar base de datos descifrada temporalmente
        with open(temp_decrypted_path, "wb") as f:
            f.write(plain_data)

    except (OSError, ValueError, TypeError, RuntimeError, InvalidTag) as e:
        asyncio.run(log_auditoria("SYSTEM", "RESTORE_DECRYPT_FAIL", f"Fallo al descifrar backup {filename}: {e!s}"))
        if os.path.exists(temp_decrypted_path):
            os.remove(temp_decrypted_path)
        msg = f"Error al descifrar el archivo de backup (clave incorrecta o archivo dañado): {e}"
        raise RuntimeError(msg)

    # 3. Validar integridad de la base de datos restaurada
    logger.info("[*] Validando integridad física del archivo SQLite descifrado...")
    try:
        conn = sqlite3.connect(temp_decrypted_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check")
        status = cursor.fetchone()[0]
        conn.close()
        if status != "ok":
            msg = f"Chequeo de integridad de SQLite falló: {status}"
            raise sqlite3.DatabaseError(msg)
    except (sqlite3.Error, OSError) as e:
        secure_delete(temp_decrypted_path)
        asyncio.run(log_auditoria("SYSTEM", "RESTORE_INTEGRITY_FAIL", f"Ruptura de integridad en base de datos de backup: {e!s}"))
        msg = f"La base de datos descifrada no es válida o está corrupta: {e}"
        raise RuntimeError(msg)

    # 4. Remplazar la base de datos de destino activa de forma segura
    if os.path.exists(target_path):
        backup_active_path = target_path + ".old"
        logger.info(f"[*] Creando backup local de la base de datos activa antes de sobrescribir: {backup_active_path}")
        if os.path.exists(backup_active_path):
            os.remove(backup_active_path)
        os.rename(target_path, backup_active_path)

    try:
        os.rename(temp_decrypted_path, target_path)
        logger.info(f"[+] Base de datos restaurada con éxito en: {target_path}")
        asyncio.run(log_auditoria("SYSTEM", "RESTORE_SUCCESS", f"Restauración completada para {db_name} desde {filename}"))

        # Eliminar el backup de la base de datos activa reemplazada
        backup_active_path = target_path + ".old"
        if os.path.exists(backup_active_path):
            os.remove(backup_active_path)

        return target_path
    except OSError as e:
        # Intentar recuperación si falla
        backup_active_path = target_path + ".old"
        if os.path.exists(backup_active_path):
            os.rename(backup_active_path, target_path)
        if os.path.exists(temp_decrypted_path):
            secure_delete(temp_decrypted_path)
        msg = f"Error al reemplazar base de datos activa: {e}"
        raise RuntimeError(msg)


def main() -> None:
    parser = argparse.ArgumentParser(description="Gestor de Backups Cifrados de BunkerOS (ENS/NIS2)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--backup", action="store_true", help="Realizar copias de seguridad de las bases de datos")
    group.add_argument("--restore", type=str, help="Ruta del archivo .enc para descifrar y restaurar")

    parser.add_argument("--db-dir", default=os.path.join(PROJECT_ROOT, "data"), help="Directorio con las bases de datos de origen")
    parser.add_argument("--backup-dir", default=os.path.join(PROJECT_ROOT, "backups"), help="Directorio destino para los backups encriptados")
    parser.add_argument("--key", help="Clave maestra para el cifrado (opcional, lee $BUNKER_MASTER_KEY)")

    args = parser.parse_args()

    # Obtener clave maestra
    master_key = args.key or os.getenv("BUNKER_MASTER_KEY")
    if not master_key:
        logger.warning("[!] ADVERTENCIA: $BUNKER_MASTER_KEY no configurada. Usando clave de desarrollo por defecto.")
        master_key = "default_dev_bunker_key_123!"

    derived_key = derive_encryption_key(master_key)

    try:
        if args.backup:
            if not os.path.exists(args.db_dir):
                logger.error(f"[-] El directorio de base de datos no existe: {args.db_dir}")
                sys.exit(1)

            # Buscar todos los archivos .db
            db_files = [os.path.join(args.db_dir, f) for f in os.listdir(args.db_dir)
                        if f.endswith(".db") and not f.startswith("test_")]

            if not db_files:
                logger.info(f"[*] No se encontraron bases de datos para respaldar en {args.db_dir}")
                sys.exit(0)

            logger.info(f"[*] Encontradas {len(db_files)} bases de datos para respaldar.")
            for db_path in db_files:
                backup_database(db_path, args.backup_dir, derived_key)
            logger.info("[+] Todas las copias de seguridad cifradas se han procesado.")

        elif args.restore:
            restore_database(args.restore, args.db_dir, derived_key)

    except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error) as e:
        logger.exception(f"[-] ERROR CRÍTICO en el gestor de backups: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
