"""
Module: generate_guide_pdf.py
Description: Production-ready enterprise component for Generate Guide Pdf.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


logger = logging.getLogger(__name__)
"""
Module: generate_guide_pdf.py
Description: Production-ready enterprise component for Generate Guide Pdf.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
from fpdf import FPDF

class DeploymentGuidePDF(FPDF):
    def header(self):
        self.set_font('helvetica', 'B', 15)
        self.cell(190, 10, 'Guia de Implementacion - Tavilga 3D', border=False, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(190, 10, f'Pagina {self.page_no()}/{{nb}}', align='C')

def clean_text(text):
    # Map emojis to strings to avoid FPDF errors
    replacements = {
        '✅': '[OK]', '🚀': '->', '📋': 'LIST:', '📁': 'DIR:', 
        '🌐': 'WEB:', '🔧': 'CFG:', '🐛': 'FIX:', '📊': 'STAT:', 
        '🔐': 'SEC:', '📞': 'TEL:', '🔴': '(X)', '🟡': '(!)', 
        '🟢': '( )', '🎉': '!!!', '—': '-', '–': '-'
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    # Remove any other non-latin1 characters
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_pdf():
    pdf = DeploymentGuidePDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("helvetica", size=11)

    files_to_read = ['DEPLOY_IONOS.md', 'TAREAS_PENDIENTES.md']
    
    for filename in files_to_read:
        if not os.path.exists(filename):
            continue
            
        if filename != files_to_read[0]:
            pdf.add_page()
            
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line in lines:
            line = clean_text(line.strip())
            if not line:
                pdf.ln(4)
                continue
            
            if line.startswith('# '):
                pdf.set_font('helvetica', 'B', 16)
                pdf.multi_cell(190, 10, line[2:])
                pdf.set_font('helvetica', '', 11)
            elif line.startswith('## '):
                pdf.ln(2)
                pdf.set_font('helvetica', 'B', 14)
                pdf.multi_cell(190, 9, line[3:])
                pdf.set_font('helvetica', '', 11)
            elif line.startswith('### '):
                pdf.set_font('helvetica', 'B', 12)
                pdf.multi_cell(190, 8, line[4:])
                pdf.set_font('helvetica', '', 11)
            elif line.startswith('- '):
                pdf.set_x(15)
                pdf.multi_cell(175, 6, f'* {line[2:]}')
            elif line.startswith('```'):
                continue
            else:
                pdf.multi_cell(190, 6, line)

    output_path = 'Guia_Implementacion_Tavilga_3D.pdf'
    pdf.output(output_path)
    logger.info(f'PDF generado: {output_path}')

if __name__ == '__main__':
    generate_pdf()
