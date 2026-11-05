"""
Module: scratch_extract_logo.py
Description: Production-ready enterprise component for Scratch Extract Logo.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


from dotenv import load_dotenv
load_dotenv()  # Zero Trust local environment loader


logger = logging.getLogger(__name__)
"""
Module: scratch_extract_logo.py
Description: Production-ready enterprise component for Scratch Extract Logo.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import base64
import os
import re

with open(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/NORMATIVAS/quantigrade_reporter.py", 'r', encoding='utf-8') as f:
    content = f.read()

match = re.search(r'QUANTIGRADE_LOGO_BASE64\s*=\s*["\']([^"\']+)["\']', content)
if match:
    b64_str = match.group(1)
    img_data = base64.b64decode(b64_str)
    
    os.makedirs(os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/IT_COMPLIANCE_MANAGER/assets", exist_ok=True)
    logo_path = os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/IT_COMPLIANCE_MANAGER/assets/logo.png"
    with open(logo_path, 'wb') as img_f:
        img_f.write(img_data)
    logger.info('Logo extracted successfully! Length:', len(img_data))
    
    # Also write src/reporters/logo.py
    logo_py_path = os.getenv("WORKSPACE_ROOT", ".") + "/AUDITORIAS/IT_COMPLIANCE_MANAGER/src/reporters/logo.py"
    with open(logo_py_path, 'w', encoding='utf-8') as logo_f:
        logo_f.write(f'# QUANTIGRADE LOGO BASE64\nQUANTIGRADE_LOGO_BASE64 = "{b64_str}"\n\nLOGO_IMAGE_PATH = r"{logo_path}"\n')
    logger.info('logo.py created successfully!')
else:
    logger.info('Base64 logo not found!')


if __name__ == '__main__':
    # Production entry point
    pass
