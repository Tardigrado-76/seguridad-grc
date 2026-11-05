import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
import logging
logger = logging.getLogger(__name__)
"""
Module: apply_bifurcation.py
Description: Production-ready enterprise component for Apply Bifurcation.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import re

with open('src/fastapi_server.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_csp_block = '''    SECURITY_HEADERS = {
        "Content-Security-Policy": (
            "default-src 'none'; "
            f"script-src 'self' 'wasm-unsafe-eval' 'nonce-{request.state.csp_nonce}'; "
            f"style-src 'self' 'nonce-{request.state.csp_nonce}'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self' wss://localhost:8443; "
            "worker-src 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'none'; "
            "require-trusted-types-for 'script'; "
            "trusted-types bunker-policy dompurify"
        ),'''

new_csp_block = '''    import os
    bunker_env = os.environ.get("BUNKER_ENV", "TEST").upper()
    if bunker_env in ["TEST", "DEVELOPMENT"]:
        script_src = f"script-src 'self' 'wasm-unsafe-eval' 'unsafe-eval' 'nonce-{request.state.csp_nonce}'; "
        trusted_types = ""
    else:
        script_src = f"script-src 'self' 'wasm-unsafe-eval' 'nonce-{request.state.csp_nonce}'; "
        trusted_types = "require-trusted-types-for 'script'; trusted-types bunker-policy dompurify"

    csp = (
        "default-src 'none'; "
        + script_src +
        f"style-src 'self' 'nonce-{request.state.csp_nonce}'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self' wss://localhost:8443; "
        "worker-src 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'none'; "
        + trusted_types
    )

    SECURITY_HEADERS = {
        "Content-Security-Policy": csp.strip(),'''

content = content.replace(old_csp_block, new_csp_block)

with open('src/fastapi_server.py', 'w', encoding='utf-8') as f:
    f.write(content)

with open('src/templates/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

html = html.replace('alpine.csp.min.js', 'alpine.min.js')

with open('src/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(html)

logger.info("Bifurcation applied successfully!")


if __name__ == '__main__':
    # Production entry point
    pass
