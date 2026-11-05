import asyncio
import base64
import contextlib
import hashlib
import json
import os
import pathlib
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FALLBACK_WORM_FILE = "bunker-hq-bff/fallback_worm.enc.log"
MAX_WORM_SIZE = 50 * 1024 * 1024  # 50 MB

def _get_dek():
    dek_hex = os.environ.get("VAULT_DEK")
    if not dek_hex:
        try:
            with open(os.environ.get("VAULT_DEK_PATH", "/vault/secrets/dek")) as f:
                dek_hex = f.read().strip()
        except (ValueError, TypeError, RuntimeError, OSError) as e:
            msg = f"VAULT_DEK ausente y VAULT_DEK_PATH inaccesible. WORM fallback desactivado: {e}"
            raise BunkerCryptographicError(msg)
    return bytes.fromhex(dek_hex)

def _write_fallback_worm_enc(actor, action, target, metadata, ip_address) -> None:
    # Rotación por tamaño
    if os.path.exists(FALLBACK_WORM_FILE) and os.path.getsize(FALLBACK_WORM_FILE) > MAX_WORM_SIZE:
        os.rename(FALLBACK_WORM_FILE, f"{FALLBACK_WORM_FILE}.{int(time.time())}")

    key = _get_dek()
    aesgcm = AESGCM(key)
    iv = os.urandom(12)

    record = {
        "id": str(uuid.uuid4()),
        "actor": actor,
        "action": action,
        "target": target,
        "metadata": metadata,
        "ipAddress": ip_address,
        "timestamp": int(time.time()),
    }
    plaintext = json.dumps(record).encode("utf-8")
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    encoded_record = f"v1:{base64.b64encode(iv).decode()}:{base64.b64encode(ciphertext).decode()}"

    with open(FALLBACK_WORM_FILE, "a") as f:
        f.write(encoded_record + "\n")

def log_worm_db(actor: str, action: str, target: str, metadata: dict, ip_address: str) -> None:
    try:
        conn = sqlite3.connect("bunker-hq-bff/bunker_dev.sqlite", timeout=5)
        c = conn.cursor()
        c.execute(
            "INSERT INTO audit_logs (id, actor, action, target, metadata, ipAddress, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
            (str(uuid.uuid4()), actor, action, target, json.dumps(metadata), ip_address),
        )
        conn.commit()
        conn.close()
    except (ValueError, TypeError, RuntimeError, OSError, sqlite3.Error): # nosec B110
        with contextlib.suppress(ValueError, TypeError, RuntimeError, OSError):
            _write_fallback_worm_enc(actor, action, target, metadata, ip_address)

import ssl

from src.bunker_exceptions import BunkerCryptographicError, BunkerSecurityError
from src.security.bunker_ids import SecurityEvent, ids_engine

_log_queue = None
_log_task = None
_syslog_consecutive_failures = 0
QUARANTINE_LOGS = []

circuit_state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
CIRCUIT_THRESHOLD = 3
CIRCUIT_COOLDOWN = 30  # seconds
_last_failure_time = 0



def enqueue_fallback_log(entry: str) -> None:
    import sqlite3
    try:
        conn = sqlite3.connect("bunker-hq-bff/siem_fallback.sqlite", timeout=5)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS fallback_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT)")
        c.execute("INSERT INTO fallback_logs (entry) VALUES (?)", (entry,))
        conn.commit()
        conn.close()
    except (ValueError, TypeError, RuntimeError, OSError): # nosec B110
        pass

def drain_fallback_logs() -> None:
    import sqlite3
    try:
        conn = sqlite3.connect("bunker-hq-bff/siem_fallback.sqlite", timeout=5)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS fallback_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT)")
        c.execute("SELECT id, entry FROM fallback_logs ORDER BY id ASC")
        rows = c.fetchall()

        if rows:
            for row in rows:
                _send_log_network(row[1])
            c.execute("DELETE FROM fallback_logs")
            conn.commit()
        conn.close()
    except (ValueError, TypeError, RuntimeError, OSError, sqlite3.Error): # nosec B110
        pass


def reconcile_worm_fallback() -> None:
    import base64
    import json
    import sqlite3

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not os.path.exists(FALLBACK_WORM_FILE):
        return

    try:
        conn = sqlite3.connect("bunker-hq-bff/bunker_dev.sqlite", timeout=5)
        c = conn.cursor()

        with open(FALLBACK_WORM_FILE) as f:
            lines = f.readlines()

        key = _get_dek()
        aesgcm = AESGCM(key)

        valid_records = []
        for line in lines:
            parts = line.strip().split(":")
            if len(parts) != 3 or parts[0] != "v1":
                continue

            iv = base64.b64decode(parts[1])
            ciphertext = base64.b64decode(parts[2])
            try:
                plaintext = aesgcm.decrypt(iv, ciphertext, None)
                record = json.loads(plaintext.decode("utf-8"))
                valid_records.append((
                    record["id"], record["actor"], record["action"],
                    record["target"], json.dumps(record["metadata"]),
                    record["ipAddress"], record["timestamp"],
                ))
            except (ValueError, TypeError, RuntimeError, OSError, InvalidTag):
                pass

        if valid_records:
            c.executemany(
                "INSERT INTO audit_logs (id, actor, action, target, metadata, ipAddress, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'))",
                valid_records,
            )
            conn.commit()

        conn.close()
        os.remove(FALLBACK_WORM_FILE)

    except (ValueError, TypeError, RuntimeError, OSError, sqlite3.Error):
        pass

def _send_log_network(entry: str) -> None:
    # Network sending logic
    bunker_env = os.getenv("BUNKER_ENV", "PROD").upper()
    if bunker_env in ["TEST", "DEVELOPMENT"]:
        siem_url = os.getenv("BUNKER_SIEM_URL", "http://127.0.0.1/mock-siem")
        req = urllib.request.Request(siem_url, data=entry.encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        if siem_url.lower().startswith("http"):
            urllib.request.urlopen(req, timeout=1.5)
        return

    syslog_host = os.getenv("BUNKER_SYSLOG_HOST", "127.0.0.1")
    syslog_port = int(os.getenv("BUNKER_SYSLOG_PORT", "6514"))
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    ca_path = str(pathlib.Path(__file__).resolve().parent.parent / "certs" / "ca.crt")
    if os.path.exists(ca_path):
        context.load_verify_locations(cafile=ca_path)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2.0)
        with context.wrap_socket(sock, server_hostname=syslog_host) as ssock:
            ssock.connect((syslog_host, syslog_port))
            ssock.sendall((entry + "\\n").encode("utf-8"))

def _send_log_sync(entry: str) -> None:
    global _syslog_consecutive_failures, circuit_state, _last_failure_time
    import time

    if circuit_state == "OPEN":
        if time.time() - _last_failure_time > CIRCUIT_COOLDOWN:
            circuit_state = "HALF_OPEN"
        else:
            enqueue_fallback_log(entry)
            return

    try:
        _send_log_network(entry)
        if circuit_state == "HALF_OPEN":
            circuit_state = "CLOSED"
            _syslog_consecutive_failures = 0
            drain_fallback_logs()
    except (ValueError, TypeError, RuntimeError, OSError):
        _syslog_consecutive_failures += 1
        _last_failure_time = time.time()
        enqueue_fallback_log(entry)
        if _syslog_consecutive_failures >= CIRCUIT_THRESHOLD:
            circuit_state = "OPEN"


async def _siem_worker_task() -> None:
    global _log_queue
    while True:
        entry = await _log_queue.get()
        try:
            await asyncio.to_thread(_send_log_sync, entry)
        except (ValueError, TypeError, RuntimeError, OSError):
            pass
        finally:
            _log_queue.task_done()


def emitir_log_remoto_worm(log_entry: str) -> None:
    global _log_queue, _log_task
    try:
        loop = asyncio.get_running_loop()
        if _log_queue is None:
            _log_queue = asyncio.Queue(maxsize=10000)
            _log_task = loop.create_task(_siem_worker_task())

        # Safe enqueue inside the running event loop
        _log_queue.put_nowait(log_entry)
    except RuntimeError:
        # Fallback to threading if called from a synchronous context without an
        # event loop
        t = threading.Thread(
            target=_send_log_sync, args=(log_entry,), daemon=True,
        )
        t.start()


_audit_lock = threading.Lock()
_LAST_LOG_HASH = "0" * 64
private_key = None


def _execute_network_lockdown(reason="") -> None:
    import subprocess  # nosec B404

    try:
        subprocess.run(
            [
                r"C:\Windows\System32\netsh.exe",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=BUNKER_LOCKDOWN",
            ],
            capture_output=True,
            timeout=5,
        )  # nosec B603 B607
        subprocess.run(
            [
                r"C:\Windows\System32\netsh.exe",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=BUNKER_LOCKDOWN",
                "dir=in",
                "action=block",
                "protocol=tcp",
                "localport=8000",
                "enable=yes",
            ],
            capture_output=True,
            timeout=5,
        )  # nosec B603 B607
    except BunkerSecurityError:
        pass


def initialize_logger() -> None:
    global private_key, _LAST_LOG_HASH

    from src.bunker_worm_guard import worm_guard
    worm_guard._initialize_state()
    _LAST_LOG_HASH = worm_guard._last_hash

    # Locate certs
    BASE_DIR = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
    key_path = str(BASE_DIR.parent / "certs" / "server.key")

    try:
        if os.path.exists(key_path):
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None,
                )
        else:
            private_key = ec.generate_private_key(ec.SECP256R1())
    except BunkerSecurityError:
        private_key = ec.generate_private_key(ec.SECP256R1())

    # Reconstruct log chain
    _LAST_LOG_HASH = "0" * 64
    log_file_path = str(BASE_DIR / "security_audit.log")
    if not os.path.exists(log_file_path):
        return
    try:
        with open(log_file_path, encoding="utf-8") as f:
            lines = f.readlines()

        temp_hash = "0" * 64
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (ValueError, TypeError, RuntimeError, OSError) as e:
                # Si falla el parseo JSON, lo mandamos a cuarentena y alertamos al SIEM
                QUARANTINE_LOGS.append({"line": i+1, "content": line, "error": str(e)})
                continue

            # Verify chaining
            prev_hash_val = entry.get("prev_hash")
            if prev_hash_val is None and isinstance(
                entry.get("bunkeros"), dict,
            ):
                prev_hash_val = entry["bunkeros"].get("prev_hash")

            if prev_hash_val != temp_hash:
                pass

            # Verify signature if possible
            signature_str = entry.get("signature")
            if signature_str and private_key:
                payload_to_verify = entry.copy()
                payload_to_verify.pop("signature", None)
                canonical = json.dumps(
                    payload_to_verify, sort_keys=True, separators=(",", ":"),
                )

                try:
                    import binascii
                    sig_bytes = base64.b64decode(signature_str.encode("utf-8"))
                    pub_key = private_key.public_key()
                    if isinstance(pub_key, ec.EllipticCurvePublicKey):
                        pub_key.verify(
                            sig_bytes,
                            canonical.encode("utf-8"),
                            ec.ECDSA(hashes.SHA256()),
                        )
                    else:
                        from cryptography.hazmat.primitives.asymmetric import (
                            padding as asymmetric_padding,
                        )

                        pub_key.verify(
                            sig_bytes,
                            canonical.encode("utf-8"),
                            asymmetric_padding.PSS(
                                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                                salt_length=asymmetric_padding.PSS.MAX_LENGTH,
                            ),
                            hashes.SHA256(),
                        )
                except (binascii.Error, ValueError) as e:
                    # Si es binascii.Error o ValueError (padding/base64 inválida), cuarentena
                    QUARANTINE_LOGS.append({"line": i+1, "content": line, "error": f"Firma corrupta: {e}"})
                    continue
                except (ValueError, TypeError, RuntimeError, OSError) as e:
                    # Cualquier otro fallo de validación
                    QUARANTINE_LOGS.append({"line": i+1, "content": line, "error": f"Error de verificación: {e}"})
                    continue

            temp_hash = hashlib.sha3_512(line.encode("utf-8")).hexdigest()

        _LAST_LOG_HASH = temp_hash
    except (ValueError, TypeError, RuntimeError, OSError):
        pass




async def log_auditoria(
    usuario: str,
    accion: str,
    detalles: str,
    mitre_id: str | None = None,
    capec_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    error_obj: Exception | None = None,
) -> None:
    global _LAST_LOG_HASH

    # 4.1 Indexación semántica automática
    if error_obj and hasattr(error_obj, "mitre_id") and not mitre_id:
        mitre_id = error_obj.mitre_id

    detalles_lower = detalles.lower()
    if not mitre_id:
        if "token bucket" in detalles_lower or "rate limit" in detalles_lower or "ddos" in detalles_lower:
            mitre_id = "T1499"
    if not capec_id:
        if "llm" in detalles_lower or "prompt injection" in detalles_lower:
            capec_id = "CAPEC-673"

    # Resolve fields for Pydantic SecurityEvent validation
    resolved_mitre_id = mitre_id or "T0000"
    resolved_capec_id = capec_id or "CAPEC-000"
    resolved_severity = "HIGH" if (mitre_id or capec_id) else "INFO"
    _ts_validation = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Strictly validate security events via Pydantic SecurityEvent model
    _sec_event = SecurityEvent(
        mitre_id=resolved_mitre_id,
        capec_id=resolved_capec_id,
        event_description=detalles,
        severity=resolved_severity,
        timestamp=_ts_validation,
        src_ip=ip_address,
    )

    # 4.2 Lógica Auto-Air-Gap — IntrusionDetectionEngine estructurado MITRE/CAPEC
    if mitre_id:
        asyncio.ensure_future(ids_engine.record_event(_sec_event))

    # Recuperación automática de hash si no ha sido inicializado
    BASE_DIR = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
    log_file_path = str(BASE_DIR / "security_audit.log")
    if _LAST_LOG_HASH == "0" * 64:
        try:
            if (
                os.path.exists(log_file_path)
                and os.path.getsize(log_file_path) > 0
            ):
                with open(log_file_path, encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in reversed(lines):
                        line = line.strip()
                        if line:
                            _LAST_LOG_HASH = hashlib.sha3_512(
                                line.encode("utf-8"),
                            ).hexdigest()
                            break
        except BunkerSecurityError:
            pass

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # 1. Prepare raw payload (Elastic Common Schema ECS 8.11+ format)
    log_payload = {
        "@timestamp": timestamp,
        "ecs": {"version": "8.11.0"},
        "event": {
            "dataset": "bunkeros.audit",
            "action": accion,
            "category": ["audit", "security"],
            "type": ["info"],
        },
        "user": {"name": usuario},
        "message": detalles,
        "host": {"hostname": socket.gethostname()},
        "bunkeros": {
            "region": "Comunidad Valenciana",
            "autoridad_competente": "APV",
            "normativa": "ENS_ALTO",
            "prev_hash": _LAST_LOG_HASH,
        },
        "mitre_id": _sec_event.mitre_id,
        "capec_id": _sec_event.capec_id,
        "event_description": _sec_event.event_description,
        "severity": _sec_event.severity,
        "timestamp": _sec_event.timestamp,
    }

    # Crypto-Shredding (RGPD)
    if ip_address or user_agent:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from src.fastapi_server import DB_USUARIOS

            kek_id = f"kek_{usuario}"
            if not await DB_USUARIOS.contains(kek_id):
                # Generate new KEK for user
                new_kek = base64.b64encode(os.urandom(32)).decode("utf-8")
                await DB_USUARIOS.set(kek_id, {"kek": new_kek})

            user_data = await DB_USUARIOS.get(kek_id)
            kek_b64 = user_data.get("kek") if user_data else None
            kek_bytes = base64.b64decode(kek_b64)
            aesgcm = AESGCM(kek_bytes)

            pii_data = json.dumps({"ip": ip_address, "ua": user_agent}).encode("utf-8")
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, pii_data, None)

            log_payload["user"]["encrypted_pii"] = base64.b64encode(nonce + ct).decode("utf-8")
            log_payload["user"]["crypto_shredding"] = "enabled"
        except BunkerSecurityError as e:
            log_payload["user"]["crypto_shredding"] = f"error: {e!s}"

    if mitre_id or capec_id:
        log_payload["threat"] = {}
        if mitre_id:
            log_payload["threat"]["tactic"] = {"id": mitre_id}
        if capec_id:
            log_payload["threat"]["technique"] = {"id": capec_id}

    from src.bunker_worm_guard import worm_guard
    try:
        final_entry = await worm_guard.atomic_write(log_payload, private_key)
        _LAST_LOG_HASH = worm_guard._last_hash
        emitir_log_remoto_worm(final_entry)
    except BunkerSecurityError:
        pass

async def verify_forensic_chain() -> dict:
    global private_key
    BASE_DIR = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
    log_file_path = str(BASE_DIR / "security_audit.log")

    manifest = {
        "chain_intact": True,
        "total_records": 0,
        "last_hash": "0" * 64,
        "tampered_lines": [],
        "signature_errors": [],
    }

    if not os.path.exists(log_file_path):
        return manifest

    try:
        with open(log_file_path, encoding="utf-8") as f:
            lines = f.readlines()

        temp_hash = "0" * 64
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            manifest["total_records"] += 1

            try:
                entry = json.loads(line)
            except (ValueError, TypeError, RuntimeError, OSError):
                manifest["chain_intact"] = False
                manifest["tampered_lines"].append({"line": i+1, "error": "JSON Parser Error"})
                continue

            prev_hash_val = entry.get("prev_hash")
            if prev_hash_val is None and isinstance(entry.get("bunkeros"), dict):
                prev_hash_val = entry["bunkeros"].get("prev_hash")

            if prev_hash_val != temp_hash:
                manifest["chain_intact"] = False
                manifest["tampered_lines"].append({"line": i+1, "error": "Hash Chain Broken"})

            signature_str = entry.get("signature")
            if signature_str and private_key:
                payload_to_verify = entry.copy()
                payload_to_verify.pop("signature", None)
                canonical = json.dumps(payload_to_verify, sort_keys=True, separators=(",", ":"))

                try:
                    sig_bytes = base64.b64decode(signature_str.encode("utf-8"))
                    pub_key = private_key.public_key()
                    if isinstance(pub_key, ec.EllipticCurvePublicKey):
                        pub_key.verify(
                            sig_bytes,
                            canonical.encode("utf-8"),
                            ec.ECDSA(hashes.SHA256()),
                        )
                    else:
                        from cryptography.hazmat.primitives.asymmetric import (
                            padding as asymmetric_padding,
                        )
                        pub_key.verify(
                            sig_bytes,
                            canonical.encode("utf-8"),
                            asymmetric_padding.PSS(
                                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                                salt_length=asymmetric_padding.PSS.MAX_LENGTH,
                            ),
                            hashes.SHA256(),
                        )
                except (ValueError, TypeError, RuntimeError, OSError) as e:
                    manifest["chain_intact"] = False
                    manifest["signature_errors"].append({"line": i+1, "error": str(e)})

            temp_hash = hashlib.sha3_512(line.encode("utf-8")).hexdigest()
            manifest["last_hash"] = temp_hash

    except (ValueError, TypeError, RuntimeError, OSError) as e:
        manifest["chain_intact"] = False
        manifest["tampered_lines"].append({"line": 0, "error": f"File Read Error: {e}"})

    return manifest
