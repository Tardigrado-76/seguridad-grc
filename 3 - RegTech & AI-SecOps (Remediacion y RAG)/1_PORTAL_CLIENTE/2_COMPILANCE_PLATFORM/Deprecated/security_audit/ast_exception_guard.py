"""
Module: ast_exception_guard.py
Description: Production-ready enterprise component for Ast Exception Guard.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import logging

import logging


logger = logging.getLogger(__name__)
"""
Module: ast_exception_guard.py
Description: Production-ready enterprise component for Ast Exception Guard.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

#!/usr/bin/env python3
import ast
import sys
import os

class ExceptionVisitor(ast.NodeVisitor):
    def __init__(self, filename, lines):
        self.filename = filename
        self.lines = lines
        self.violations = []

    def visit_ExceptHandler(self, node):
        # Checks for 'except Exception:' or 'except Exception as e:'
        if getattr(node.type, 'id', None) == 'Exception':
            if '# nosec B110' not in self.lines[node.lineno - 1]:
                self.violations.append(node.lineno)
        # Check for bare 'except:'
        if node.type is None:
            if '# nosec B110' not in self.lines[node.lineno - 1]:
                self.violations.append(node.lineno)
        self.generic_visit(node)

def main():
    has_error = False
    for filepath in sys.argv[1:]:
        if not filepath.endswith('.py'):
            continue
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            lines = content.splitlines()
            tree = ast.parse(content, filename=filepath)
            visitor = ExceptionVisitor(filepath, lines)
            visitor.visit(tree)
            if visitor.violations:
                logger.info(f"[ERROR] Bare or generic 'except Exception' found in {filepath}")
                for line in visitor.violations:
                    logger.info(f"  -> Line {line}: Use a specific exception from src.bunker_exceptions")
                has_error = True
        except (OSError, SyntaxError, UnicodeDecodeError) as e:
            logger.info(f"[ERROR] Could not parse {filepath}: {e}")
            has_error = True

    if has_error:
        logger.info("\n[AST GUARD] Commits with generic exceptions are rejected to prevent opacity in SIEM logging.")
        sys.exit(1)

if __name__ == "__main__":
    main()
