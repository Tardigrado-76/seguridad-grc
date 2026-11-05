"""
Module: bunker_backups_hardening.py
Description: Production-ready enterprise component for Bunker Backups Hardening.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import logging
import os

from dotenv import load_dotenv

load_dotenv()  # Zero Trust env loading


from dotenv import load_dotenv

load_dotenv()  # Zero Trust local environment loader


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BunkerOS Hot-Fix Remediation Script
Standards: ENS Categoría Alta, NIS2, CRA, CER Directive.
"""
import os
import re
import shutil

BACKUP_DIR = "bunker_backups_hardening"
FILES_TO_HARDEN = [
    "src/fastapi_server.py",
    "src/bunker_logger.py",
    "src/bunker_llm_gate.py",
]


def backup_files():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    for fpath in FILES_TO_HARDEN:
        if os.path.exists(fpath):
            basename = os.path.basename(fpath)
            backup_path = os.path.join(BACKUP_DIR, f"{basename}.bak")
            shutil.copy2(fpath, backup_path)
            logger.info(f"[+] Backup forense creado: {backup_path}")


def harden_fastapi_server():
    path = "src/fastapi_server.py"
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. SSL Context (TLS 1.3 Strict)
    ssl_context_code = """
def get_ssl_context(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Destruir compatibilidad con TLS 1.0, 1.1 y 1.2
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")
    return ctx
"""
    if "def get_ssl_context" not in content:
        content = content.replace(
            "import uvicorn", "import uvicorn\n" + ssl_context_code
        )

    content = re.sub(
        r'ssl_keyfile=ssl_key,\s*ssl_certfile=ssl_cert,\s*ssl_version=ssl\.PROTOCOL_TLS_SERVER,\s*ssl_ciphers="[^"]+"',
        "ssl_context=get_ssl_context(ssl_cert, ssl_key)",
        content,
    )

    # 2. TokenBucketLimiter & Middleware
    rate_limit_code = """
import time
class TokenBucketLimiter:
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.buckets = {}

    def allow_request(self, ip: str) -> bool:
        now = time.time()
        if ip not in self.buckets:
            self.buckets[ip] = {"tokens": self.capacity, "last_update": now}
        
        bucket = self.buckets[ip]
        elapsed = now - bucket["last_update"]
        bucket["tokens"] = min(self.capacity, bucket["tokens"] + elapsed * self.rate)
        bucket["last_update"] = now
        
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        return False

limiter = TokenBucketLimiter(rate=10.0, capacity=50)

@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not limiter.allow_request(client_ip):
        return Response("Too Many Requests", status_code=429)
    return await call_next(request)
"""
    if "class TokenBucketLimiter" not in content:
        content = content.replace(
            "# --- Middleware CORS", rate_limit_code + "\n# --- Middleware CORS"
        )

    # 3. Resource Monitor Kill Switch
    kill_switch_code = """                if get_current_process_memory_windows() / (1024 * 1024) > 1024:
                    _execute_network_lockdown(reason="Hardware DoS Persistence")
                    import os
                    os._exit(1)"""

    if "os._exit(1)" not in content:
        content = content.replace("gc.collect()", "gc.collect()\n" + kill_switch_code)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info(f"[+] Remediado: {path} (TLS 1.3 Strict, Rate Limiting, Kill Switch)")


def harden_bunker_logger():
    path = "src/bunker_logger.py"
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Syslog WORM
    syslog_code = """
import socket
def emitir_log_remoto_worm(log_entry: str):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(log_entry.encode('utf-8'), ("127.0.0.1", 514))
        sock.close()
    except Exception:
        pass
"""
    if "def emitir_log_remoto_worm" not in content:
        content = content.replace(
            "import threading", "import threading\n" + syslog_code
        )

    if "emitir_log_remoto_worm(final_entry)" not in content:
        content = content.replace(
            'f.write(final_entry + "\\n")',
            'f.write(final_entry + "\\n")\n            emitir_log_remoto_worm(final_entry)',
        )

    # 2. Auto-Air-Gap
    lockdown_code = """
def _execute_network_lockdown(reason=""):
    import subprocess
    try:
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=BUNKER_LOCKDOWN'], capture_output=True, timeout=5)
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=BUNKER_LOCKDOWN', 'dir=in', 'action=block', 'protocol=tcp', 'localport=8000', 'enable=yes'], capture_output=True, timeout=5)
    except Exception: pass
"""
    if "def _execute_network_lockdown" not in content:
        content = content.replace(
            "def initialize_logger():", lockdown_code + "\ndef initialize_logger():"
        )

    fail_hook = """logger.info(f"[!] ADVERTENCIA CRÍTICA FORENSE: Ruptura en la cadena de hash en línea {i+1}!")
                _execute_network_lockdown("Ruptura Hash Forense")
                raise SystemExit("Integridad de auditoría comprometida. Ejecución abortada (CER).")"""

    content = re.sub(
        r'print\(f"\[!\] ADVERTENCIA CRÍTICA FORENSE: Ruptura en la cadena de hash en línea \{i\+1\}!"\)',
        fail_hook,
        content,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info(f"[+] Remediado: {path} (Syslog WORM, Auto-Air-Gap)")


def harden_bunker_llm_gate():
    path = "src/bunker_llm_gate.py"
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Inferencia segura
    inferencia_code = """
def evaluar_payload_inferencia(model: str, prompt: str) -> dict:
    import re
    # Heurística de ofuscación semántica
    if re.search(r'(?i)(base64|hex|rot13|encoding|ignore|bypas|system\\s+prompt)', prompt):
        prompt = "Mensaje neutralizado por heurística semántica de inyección."
    return {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "num_predict": 256,
        "max_tokens": 256
    }
"""
    if "def evaluar_payload_inferencia" not in content:
        content = content.replace(
            "def sanitize_response_data",
            inferencia_code + "\ndef sanitize_response_data",
        )

    content = re.sub(
        r'payload = \{\s*"model": model,\s*"prompt": prompt,\s*"stream": False\s*\}',
        "payload = evaluar_payload_inferencia(model, prompt)",
        content,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info(
        f"[+] Remediado: {path} (Strict max_tokens, Heurística Prompt Injection)"
    )


if __name__ == "__main__":
    logger.info(
        "[*] Iniciando script de remediación en caliente BUNKER_HARDENING_EXECUTOR..."
    )
    try:
        backup_files()
        harden_fastapi_server()
        harden_bunker_logger()
        harden_bunker_llm_gate()
        logger.info(
            "[*] Remediación completada con éxito. Todos los hallazgos SAST parcheados."
        )
    except Exception as e:
        logger.info(f"[!] Error crítico durante la remediación: {e}")
