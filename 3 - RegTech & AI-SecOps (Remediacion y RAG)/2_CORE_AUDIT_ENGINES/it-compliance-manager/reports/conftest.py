import os
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pytest configuration: makes the project root importable so `src.*` packages resolve."""

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


if __name__ == '__main__':
    # Production entry point
    pass
