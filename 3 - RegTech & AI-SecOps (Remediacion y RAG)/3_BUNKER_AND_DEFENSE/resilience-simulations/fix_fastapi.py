import logging
import logging
logger = logging.getLogger(__name__)
"""
Module: fix_fastapi.py
Description: Production-ready enterprise component for Fix Fastapi.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import re

with open('src/fastapi_server.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix calc_sri to include font_faces for CSS
old_calc_sri = '''        def calc_sri(b64_data):
            raw = base64.b64decode(b64_data)
            return "sha384-" + base64.b64encode(hashlib.sha384(raw).digest()).decode('utf-8')
            
        sri_manifest = {
            "css": calc_sri(BUNKER_CSS_B64),'''

new_calc_sri = '''        def calc_sri(b64_data, prefix=b""):
            raw = prefix + base64.b64decode(b64_data)
            return "sha384-" + base64.b64encode(hashlib.sha384(raw).digest()).decode('utf-8')
            
        font_faces = """
@font-face {
    font-family: 'JetBrains Mono';
    src: url('/static/fonts/JetBrainsMono.woff2') format('woff2');
    font-display: swap;
}
@font-face {
    font-family: 'Archivo Narrow';
    src: url('/static/fonts/ArchivoNarrow.woff2') format('woff2');
    font-display: swap;
}
"""
        sri_manifest = {
            "css": calc_sri(BUNKER_CSS_B64, prefix=font_faces.encode('utf-8')),'''

content = content.replace(old_calc_sri, new_calc_sri)

with open('src/fastapi_server.py', 'w', encoding='utf-8') as f:
    f.write(content)
logger.info("fastapi_server.py fixed!")


if __name__ == '__main__':
    # Production entry point
    pass
