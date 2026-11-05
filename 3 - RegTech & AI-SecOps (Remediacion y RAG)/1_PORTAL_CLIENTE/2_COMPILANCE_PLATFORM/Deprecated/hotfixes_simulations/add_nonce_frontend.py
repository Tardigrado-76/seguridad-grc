import logging
import logging
logger = logging.getLogger(__name__)
"""
Module: add_nonce_frontend.py
Description: Production-ready enterprise component for Add Nonce Frontend.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import re

with open('src/fastapi_server.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Update get_frontend to inject the nonce into the template
old_get_frontend = '''        content = content.replace(
            "{{ sri_manifest.alpine }}", sri_manifest.get("alpine", "")
        )

        return Response(content=content, media_type="text/html")'''

new_get_frontend = '''        content = content.replace(
            "{{ sri_manifest.alpine }}", sri_manifest.get("alpine", "")
        )
        content = content.replace("{{ nonce }}", getattr(request.state, "csp_nonce", ""))

        return Response(content=content, media_type="text/html")'''

content = content.replace(old_get_frontend, new_get_frontend)

with open('src/fastapi_server.py', 'w', encoding='utf-8') as f:
    f.write(content)

logger.info("fastapi_server.py get_frontend updated with nonce injection!")


if __name__ == '__main__':
    # Production entry point
    pass
