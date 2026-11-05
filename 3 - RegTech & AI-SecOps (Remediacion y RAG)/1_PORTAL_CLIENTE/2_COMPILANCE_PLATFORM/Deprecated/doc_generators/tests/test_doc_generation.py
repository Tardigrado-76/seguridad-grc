"""
Document Generation Functional Tests
"""



import pytest
import os

def test_reportlab_importable():
    try:
        import reportlab
        assert reportlab.__version__ is not None
    except ImportError:
        pytest.skip("Reportlab not installed in test env")

def test_fpdf_importable():
    try:
        import fpdf
        assert fpdf is not None
    except ImportError:
        pytest.skip("fpdf not installed in test env")
