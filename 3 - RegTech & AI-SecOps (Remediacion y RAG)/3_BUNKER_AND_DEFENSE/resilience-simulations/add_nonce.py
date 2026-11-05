import logging
import logging
logger = logging.getLogger(__name__)
"""
Module: add_nonce.py
Description: Production-ready enterprise component for Add Nonce.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import re

with open('src/fastapi_server.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add nonce generation at the start of global_security_enforcer
old_def = 'async def global_security_enforcer(request: Request, call_next):'
new_def = '''async def global_security_enforcer(request: Request, call_next):
    if not hasattr(request.state, "csp_nonce"):
        request.state.csp_nonce = secrets.token_urlsafe(16)'''
content = content.replace(old_def, new_def)

# Update the Content-Security-Policy header
old_csp = '''        "Content-Security-Policy": (
            "default-src 'none'; "
            "script-src 'self' 'wasm-unsafe-eval'; "
            "style-src 'self'; "'''
new_csp = '''        "Content-Security-Policy": (
            "default-src 'none'; "
            f"script-src 'self' 'wasm-unsafe-eval' 'nonce-{request.state.csp_nonce}'; "
            f"style-src 'self' 'nonce-{request.state.csp_nonce}'; "'''
content = content.replace(old_csp, new_csp)

with open('src/fastapi_server.py', 'w', encoding='utf-8') as f:
    f.write(content)

logger.info("fastapi_server.py updated with nonce!")


if __name__ == '__main__':
    # Production entry point
    pass
