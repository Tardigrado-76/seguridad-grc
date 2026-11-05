"""bunker_digital_suicide.py — BunkerOS NIST 800-88 Secure Erasure Protocol.
=========================================================================
Implements the "Digital Suicide" protocol for emergency data destruction.
Multi-pass overwrite (NIST 800-88 Rev.1 Clear/Purge) of all sensitive
cryptographic material, logs, certificates, and databases.

Triggered by: USB disconnection, VM detection, or manual LOCKDOWN.

Compliance: ENS Alta, NIS2 Art.21 (resilience), CRA Art.13, NIST 800-88.
"""

import contextlib
import gc
import logging
import os
import pathlib
import shutil
import sys
import threading
from datetime import datetime, timezone

from src.bunker_logger import log_auditoria

logger = logging.getLogger("BunkerOS.DigitalSuicide")

_ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent

# ─── Target Manifest (files/dirs to purge under compromise) ──────────────────

PURGE_TARGETS = {
    "logs": [
        _ROOT_DIR / "security_audit.log",
        _ROOT_DIR / "bunker_secure.log",
        _ROOT_DIR / "security_audit.wal",
        _ROOT_DIR / "logs",
    ],
    "certificates": [
        _ROOT_DIR / "certs",
        _ROOT_DIR / "ec-private.pem",
        _ROOT_DIR / "ec-public.pem",
        _ROOT_DIR / "security" / "sbom_private.pem",
    ],
    "database": [
        _ROOT_DIR / "data" / "bunker.db",
    ],
    "keys": [
        _ROOT_DIR / "bunker_keys",
        _ROOT_DIR / "keys",
        _ROOT_DIR / ".bunker_secure",
    ],
    "environment": [
        "BUNKER_MASTER_KEY",
        "BUNKER_ADMIN_TOKEN",
        "BUNKER_JWT_SECRET",
    ],
}


# ─── NIST 800-88 Multi-Pass Secure Overwrite ─────────────────────────────────


def _nist_800_88_overwrite(filepath: str, passes: int = 3) -> bool:
    """Overwrite a file using NIST 800-88 Rev.1 Clear method.

    Pass 1: Binary zeros (0x00)
    Pass 2: Binary ones  (0xFF)
    Pass 3: Cryptographic random data (os.urandom)

    After overwrite, the file is deleted.

    Args:
        filepath: Absolute path to the file.
        passes: Number of overwrite passes (minimum 3 per NIST 800-88).

    Returns:
        True if successfully purged, False on error.

    """
    try:
        if not os.path.isfile(filepath):
            return False

        file_size = os.path.getsize(filepath)
        if file_size == 0:
            os.remove(filepath)
            return True

        # Use a buffer to avoid allocating huge blocks for large files
        chunk_size = min(file_size, 1024 * 1024)  # 1MB chunks

        with open(filepath, "r+b") as f:
            for pass_num in range(passes):
                f.seek(0)
                remaining = file_size

                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    if pass_num == 0:
                        data = b"\x00" * write_size
                    elif pass_num == 1:
                        data = b"\xff" * write_size
                    else:
                        data = os.urandom(write_size)

                    f.write(data)
                    remaining -= write_size

                f.flush()
                os.fsync(f.fileno())

        os.remove(filepath)
        logger.info(
            f"[NIST-800-88] PURGED: {filepath} ({passes} passes, {file_size} bytes)",
        )
        return True

    except PermissionError:
        logger.exception(f"[NIST-800-88] Permission denied: {filepath}")
        return False
    except (ValueError, TypeError, RuntimeError, OSError) as e:
        logger.exception(f"[NIST-800-88] Error purging {filepath}: {e}")
        # Attempt simple deletion as fallback
        with contextlib.suppress(OSError):
            os.remove(filepath)
        return False


def execute_graceful_suicide() -> None:
    """Protocolo de Degradación Grácil: Contención Táctica y Forense.
    Ejecuta en < 50ms: aísla hilo, purga RAM (Zeroization), emite log,
    y termina el proceso (Exit 137) para que K8s aísle el Pod.
    """
    # 1. Emitir alerta CRITICAL_TAMPERING al bus WORM (Logger inmutable)
    log_auditoria(
        "CRITICAL_TAMPERING",
        "RUNTIME_COMPROMISE",
        "Intrusión detectada en memoria. Iniciando purga y degradación.",
    )

    # 2. Revocar y Zeroization de secretos en RAM (Simulado con GC y
    # sobrescritura de env)
    from src.security.bunker_memory_guard import shred_all
    with contextlib.suppress(ValueError, TypeError, RuntimeError, OSError):
        shred_all()

    if "BUNKER_JWT_SECRET" in os.environ:
        os.environ["BUNKER_JWT_SECRET"] = "\x00" * len(
            os.environ["BUNKER_JWT_SECRET"],
        )
    if "BUNKER_MASTER_KEY" in os.environ:
        os.environ["BUNKER_MASTER_KEY"] = "\x00" * len(
            os.environ["BUNKER_MASTER_KEY"],
        )
    gc.collect()

    # 3. Terminar proceso con Exit Code 137 para cuarentena K8s
    log_auditoria(
        "SYSTEM",
        "SUICIDE_COMPLETE",
        "Terminando proceso de FastAPI (Exit 137)",
    )
    os._exit(137)


def _secure_purge_directory(dir_path: str) -> int:
    """Recursively purge all files in a directory using NIST 800-88."""
    purged = 0
    dir_path = str(dir_path)
    if not os.path.isdir(dir_path):
        return 0

    for root, dirs, files in os.walk(dir_path, topdown=False):
        for fname in files:
            fpath = os.path.join(root, fname)
            if _nist_800_88_overwrite(fpath):
                purged += 1
        for dname in dirs:
            with contextlib.suppress(OSError):
                os.rmdir(os.path.join(root, dname))

    with contextlib.suppress(ValueError, TypeError, RuntimeError, OSError):
        shutil.rmtree(dir_path, ignore_errors=True)

    return purged


def _purge_environment_keys() -> int:
    """Zeroize and delete sensitive environment variables."""
    purged = 0
    for var_name in PURGE_TARGETS["environment"]:
        if var_name in os.environ:
            original_len = len(os.environ[var_name])
            os.environ[var_name] = "0" * original_len
            del os.environ[var_name]
            purged += 1
            logger.info(f"[NIST-800-88] ENV purged: {var_name}")
    return purged


# ─── Main Digital Suicide Protocol ───────────────────────────────────────────

_SUICIDE_LOCK = threading.Lock()
_SUICIDE_EXECUTED = False


def execute_digital_suicide(reason: str = "Unspecified compromise") -> dict:
    """Execute the full Digital Suicide protocol.

    This is an IRREVERSIBLE operation that securely destroys:
    - All log files (security_audit.log, bunker_secure.log)
    - All TLS/mTLS certificates and private keys
    - The encrypted database (bunker.db)
    - All cached cryptographic keys
    - Sensitive environment variables

    Args:
        reason: The triggering reason for forensic logging.

    Returns:
        Summary dict of the purge operation.

    """
    global _SUICIDE_EXECUTED

    with _SUICIDE_LOCK:
        if _SUICIDE_EXECUTED:
            return {"status": "ALREADY_EXECUTED"}

        _SUICIDE_EXECUTED = True

    timestamp = datetime.now(timezone.utc).isoformat()
    logger.critical(
        f"[DIGITAL SUICIDE] *** PROTOCOL INITIATED *** Reason: {reason}",
    )

    report = {
        "timestamp": timestamp,
        "reason": reason,
        "files_purged": 0,
        "dirs_purged": 0,
        "env_purged": 0,
        "categories": {},
    }

    # 1. Purge files and directories by category
    for category, targets in PURGE_TARGETS.items():
        if category == "environment":
            continue

        cat_count = 0
        for target in targets:
            target_path = str(target)
            if os.path.isfile(target_path):
                if _nist_800_88_overwrite(target_path):
                    cat_count += 1
                    report["files_purged"] += 1
            elif os.path.isdir(target_path):
                count = _secure_purge_directory(target_path)
                cat_count += count
                report["files_purged"] += count
                report["dirs_purged"] += 1

        report["categories"][category] = cat_count

    # 2. Purge environment variables
    report["env_purged"] = _purge_environment_keys()

    # 3. Force garbage collection to clear memory references
    gc.collect()

    logger.critical(
        f"[DIGITAL SUICIDE] COMPLETE — "
        f'Files: {report["files_purged"]}, '
        f'Dirs: {report["dirs_purged"]}, '
        f'Env: {report["env_purged"]}',
    )

    return report


# ─── EventBus Integration ────────────────────────────────────────────────────


def register_with_eventbus(bus) -> None:
    """Register Digital Suicide handlers with the BunkerOS EventBus.
    Triggers on USB_DISCONNECTED and VM_DETECTED events.
    """
    from src.bunker_event_bus import EVENT_USB_DISCONNECTED, EVENT_VM_DETECTED

    def _on_usb_disconnect(event: dict) -> None:
        execute_digital_suicide(reason=f'USB key disconnected: {
                event.get(
                    "payload", {}).get(
                    "drive", "?")}')
        sys.exit(99)

    def _on_vm_detected(event: dict) -> None:
        execute_digital_suicide(reason=f'Hypervisor detected: {
                event.get(
                    "payload", {}).get(
                    "vendor", "?")}')
        sys.exit(99)

    bus.subscribe(EVENT_USB_DISCONNECTED, _on_usb_disconnect)
    bus.subscribe(EVENT_VM_DETECTED, _on_vm_detected)
    logger.info(
        "[DigitalSuicide] Registered with EventBus (USB_DISCONNECTED, VM_DETECTED).",
    )


# ─── CLI Entrypoint ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s",
    )


    confirm = input('\nType "CONFIRM DESTROY" to proceed: ').strip()
    if confirm != "CONFIRM DESTROY":
        sys.exit(0)

    result = execute_digital_suicide(reason="Manual CLI invocation")
