"""
Script para compilar el Dictamen Estrategico:
Ranking por Categoria de Compania, Orden de Uso y Estrategia Comercial de Soluciones GRC & SecOps.
Diseno profesional editorial con ReportLab, cabeceras corporativas, logo oficial y tablas estilizadas.
"""

import os
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable,
    Image,
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Canvas corporativo con pie de pagina numerado y barra de confidencialidad."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_footer(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0f172a"))
        self.drawString(36, 26, "QUANTIGRADE GCR ENTERPRISE")
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(170, 26, "|  Dictamen Estrategico: Categorias, Ciclo de Vida y Go-To-Market")
        
        page_num = getattr(self, "_pageNumber", 1)
        footer_text = f"Pagina {page_num} de {page_count}"
        self.drawRightString(A4[0] - 36, 26, footer_text)
        
        # Linea divisoria superior del pie
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 36, A4[0] - 36, 36)
        self.restoreState()


def build_ranking_pdf(output_pdf_path: str, logo_path: str):
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=46
    )

    styles = getSampleStyleSheet()

    # Estilos tipograficos
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#2563eb"),
        spaceAfter=12
    )
    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11.5,
        leading=15,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155")
    )
    body_bold = ParagraphStyle(
        'DocBodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a")
    )
    cell_header = ParagraphStyle(
        'CellHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white,
        alignment=1  # Centered
    )
    cell_body = ParagraphStyle(
        'CellBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.2,
        leading=9.5,
        textColor=colors.HexColor("#1e293b")
    )
    cell_body_bold = ParagraphStyle(
        'CellBodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.2,
        leading=9.5,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # 1. Cabecera con Logo y Metadatos
    header_data = []
    if os.path.exists(logo_path):
        img = Image(logo_path, width=44, height=44)
        info_text = Paragraph(
            "<b>QUANTIGRADE GCR & AI-SECOPS APPLIANCE</b><br/>"
            "<font color='#64748b' size='7.5'>Ecosistema Integral de Ciberseguridad, Resiliencia Operativa y Cumplimiento Regulatorio Europeo</font><br/>"
            "<font color='#0284c7' size='7'>DORA | NIS2 | ENS Categoría Alta | EU AI Act | CRA | RGPD | Mandato PQC FIPS 204</font>",
            body_style
        )
        meta_box = Paragraph(
            "<b>FECHA:</b> Noviembre 2026<br/>"
            "<b>DOCUMENTO:</b> DICT-GCR-ESTRATEGIA-01<br/>"
            "<b>CLASIFICACIÓN:</b> ESTRATÉGICO / C-SUITE",
            ParagraphStyle('MetaBox', parent=body_style, fontSize=7, leading=9.5, alignment=2)
        )
        header_table = Table([[img, info_text, meta_box]], colWidths=[52, 330, 140])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(header_table)
    else:
        story.append(Paragraph("<b>QUANTIGRADE GCR & AI-SECOPS SUITE</b>", title_style))

    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1e293b"), spaceBefore=2, spaceAfter=8))

    # Titulo Principal
    story.append(Paragraph("Dictamen Estratégico de Arquitectura y Go-To-Market", title_style))
    story.append(Paragraph("Análisis comparativo, categorización de clientes, ciclo de vida de adopción y modelo de monetización", subtitle_style))

    # SECCION 1: Categorias de Compania
    story.append(Paragraph("1. Ranking por Categoría de Compañía (Target y Product-Market Fit)", h2_style))
    story.append(Paragraph(
        "Clasificación y priorización de las 4 soluciones tecnológicas en función del volumen de facturación, "
        "complejidad de infraestructura y grado de supervisión regulatoria (Banco de España, EBA, CNMV, CCN-CERT):",
        body_style
    ))
    story.append(Spacer(1, 4))

    cat_table_data = [
        [
            Paragraph("Ranking / Tier", cell_header),
            Paragraph("Tipo de Compañía / Perfil", cell_header),
            Paragraph("Solución Asignada", cell_header),
            Paragraph("Justificación Estratégica y Beneficio Clave", cell_header)
        ],
        [
            Paragraph("<b>#1</b> (Entrada)", cell_body_bold),
            Paragraph("<b>PYMEs, Startups Tech y Despachos de Consultoría GRC</b><br/><i>(Facturación: 1M€ - 15M€)</i>", cell_body),
            Paragraph("<b>COMPLIANCE SENTINEL</b><br/><i>(GRC-as-a-Code)</i>", cell_body_bold),
            Paragraph("Sin equipo de seguridad dedicado. Requieren diagnóstico instantáneo en un clic (.bat/Streamlit) con 4 jueces IA para presentar brechas al CEO en <10 minutos.", cell_body)
        ],
        [
            Paragraph("<b>#2</b> (Técnico)", cell_body_bold),
            Paragraph("<b>Scale-ups B2B, SaaS, Factorías Software y Proveedores Cloud</b><br/><i>(Facturación: 10M€ - 50M€)</i>", cell_body),
            Paragraph("<b>CTEM VALIDATION SUITE</b><br/><i>(Continuous Exposure Mgmt)</i>", cell_body_bold),
            Paragraph("Disponen de CI/CD. Precisan pentesting continuo, auditoría IAM, inyección de caos y validación de APIs para superar el Security Due Diligence de clientes B2B.", cell_body)
        ],
        [
            Paragraph("<b>#3</b> (Operativo)", cell_body_bold),
            Paragraph("<b>Medianas Empresas, Sanidad, Industria y Entidades NIS2</b><br/><i>(Facturación: 30M€ - 150M€)</i>", cell_body),
            Paragraph("<b>REGTECH & AI-SECOPS APPLIANCE</b>", cell_body_bold),
            Paragraph("Equipos IT/SecOps mixtos. Requieren portal unificado y <b>remediación activa automática</b> (CLARA FIX TOOLS para bastionado de Windows/Linux) con control de IA.", cell_body)
        ],
        [
            Paragraph("<b>#4</b> (Enterprise)", cell_body_bold),
            Paragraph("<b>Banca, Aseguradoras, Telcos e Infraestructuras Críticas</b><br/><i>(Facturación: > 100M€ / Reguladas)</i>", cell_body),
            Paragraph("<b>QUANTIGRADE GRC</b><br/><i>(Enterprise Suite)</i>", cell_body_bold),
            Paragraph("Bajo inspección formal (BdE/EBA/CCN). Requieren estándar Air-Gap militar, custodia WORM inmutable con criptografía post-cuántica FIPS 204 y certificación SLSA L3+.", cell_body)
        ]
    ]

    t_cat = Table(cat_table_data, colWidths=[60, 140, 115, 207])
    t_cat.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_cat)

    story.append(Spacer(1, 8))

    # SECCION 2: Ciclo de Vida y Orden de Uso
    story.append(Paragraph("2. Secuencia Metodológica y Orden de Uso en una Organización", h2_style))
    story.append(Paragraph(
        "Secuencia cronológica y operativa recomendada para implantar el marco de ciberseguridad y cumplimiento sin fricciones:",
        body_style
    ))
    story.append(Spacer(1, 4))

    seq_table_data = [
        [
            Paragraph("Fase / Cronograma", cell_header),
            Paragraph("Solución Aplicada", cell_header),
            Paragraph("Acción Operativa y Metodología", cell_header),
            Paragraph("Entregable / Resultado", cell_header)
        ],
        [
            Paragraph("<b>Fase 1</b><br/>Día 1", cell_body_bold),
            Paragraph("<b>COMPLIANCE SENTINEL</b>", cell_body_bold),
            Paragraph("Diagnóstico inicial conversacional con el Consejo de 4 Jueces IA sobre DORA, NIS2, ENS y AI Act.", cell_body),
            Paragraph("Foto preliminar ejecutiva y matriz de brechas para el C-Level sin alterar servidores.", cell_body)
        ],
        [
            Paragraph("<b>Fase 2</b><br/>Semanas 2 - 4", cell_body_bold),
            Paragraph("<b>CTEM VALIDATION SUITE</b>", cell_body_bold),
            Paragraph("Validación empírica en sistemas: simulación de caos DORA, Cloud Exit RTO/RPO, pruebas IAM y APIs.", cell_body),
            Paragraph("Informe técnico de vulnerabilidades reales, credenciales expuestas y fallos de resiliencia.", cell_body)
        ],
        [
            Paragraph("<b>Fase 3</b><br/>Mes 2", cell_body_bold),
            Paragraph("<b>REGTECH & AI-SECOPS APPLIANCE</b>", cell_body_bold),
            Paragraph("Ejecución de parches de bastionado masivo (CLARAfix ENS Alta), supervisión RAG y monitorización continua.", cell_body),
            Paragraph("Servidores Windows/Linux endurecidos con opción de rollback y gobernanza LLM activa.", cell_body)
        ],
        [
            Paragraph("<b>Fase 4</b><br/>Continuo", cell_body_bold),
            Paragraph("<b>QUANTIGRADE GRC</b>", cell_body_bold),
            Paragraph("Certificación legal inmutable, custodia WORM post-cuántica (ML-DSA) y atestación SLSA Nivel 3+.", cell_body),
            Paragraph("Dossier probatorio con validez legal y forense ante el Banco de España, CNMV y CCN-CERT.", cell_body)
        ]
    ]

    t_seq = Table(seq_table_data, colWidths=[65, 115, 192, 150])
    t_seq.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_seq)

    story.append(Spacer(1, 8))

    # SECCION 3: Estrategia Comercial (Go-To-Market)
    story.append(Paragraph("3. Estrategia Comercial (Go-To-Market) y Modelo 'Land & Expand'", h2_style))
    story.append(Paragraph(
        "Estructura comercial para monetizar el ecosistema progresivamente, desde la captación inicial hasta contratos corporativos anuales recurrentes (ARR):",
        body_style
    ))
    story.append(Spacer(1, 4))

    com_table_data = [
        [
            Paragraph("Nivel Comercial", cell_header),
            Paragraph("Producto", cell_header),
            Paragraph("Propuesta de Valor Comercial", cell_header),
            Paragraph("Modelo de Precio", cell_header),
            Paragraph("Ticket Estimado (ARR)", cell_header)
        ],
        [
            Paragraph("<b>Nivel 1</b><br/><i>Lead Magnet</i>", cell_body_bold),
            Paragraph("<b>COMPLIANCE SENTINEL</b>", cell_body),
            Paragraph("<i>'Auditoría Exprés DORA/NIS2 en 48 Horas'</i>. Abre cuentas de clientes sin fricción técnica.", cell_body),
            Paragraph("Servicio puntual o freemium con consultoría", cell_body),
            Paragraph("<b>3.000 € - 6.000 €</b><br/><i>(o demo gratuita)</i>", cell_body_bold)
        ],
        [
            Paragraph("<b>Nivel 2</b><br/><i>Auditoría Técnica</i>", cell_body_bold),
            Paragraph("<b>CTEM VALIDATION SUITE</b>", cell_body),
            Paragraph("<i>'Simulacro Activo de Caos, Salida Cloud y Pruebas TLPT'</i>. Reemplaza consultorías caras de Big Four.", cell_body),
            Paragraph("Suscripción anual por repo o por escaneo", cell_body),
            Paragraph("<b>15.000 € - 35.000 €</b>", cell_body_bold)
        ],
        [
            Paragraph("<b>Nivel 3</b><br/><i>Plataforma Activa</i>", cell_body_bold),
            Paragraph("<b>REGTECH APPLIANCE</b>", cell_body),
            Paragraph("<i>'Endurecimiento automatizado de servidores, RAG regulado y cuadro de mandos multi-área'</i>.", cell_body),
            Paragraph("Licencia anual privada por servidor / nodo", cell_body),
            Paragraph("<b>40.000 € - 75.000 €</b>", cell_body_bold)
        ],
        [
            Paragraph("<b>Nivel 4</b><br/><i>Enterprise Core</i>", cell_body_bold),
            Paragraph("<b>QUANTIGRADE GRC</b>", cell_body),
            Paragraph("<i>'Certificación continua grado militar, custodia post-cuántica y blindaje ante Banco de España y CCN'</i>.", cell_body),
            Paragraph("Contrato Enterprise anual con SLA 24/7 y WORM", cell_body),
            Paragraph("<b>90.000 € - 180.000 €+</b>", cell_body_bold)
        ]
    ]

    t_com = Table(com_table_data, colWidths=[65, 95, 172, 105, 85])
    t_com.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_com)

    story.append(Spacer(1, 10))

    # Bloque de Certificacion y Firmas
    sign_box = [
        [
            Paragraph("<b>VALIDACIÓN ESTRATÉGICA Y GOBERNANZA</b><br/>"
                      "Dictamen emitido conforme a las directivas DORA (UE 2022/2554), NIS2 (UE 2022/2555), ENS (RD 311/2022) y EU AI Act.<br/>"
                      "Atestación de integridad de diseño y custodia bajo estándares SLSA Nivel 3+ y FIPS 204.", cell_body),
            Paragraph("<b>DIRECCIÓN DE SEGURIDAD (CISO) / CONSEJO</b><br/>"
                      "<i>Certificado digitalmente con firma algorítmica de no repudio.</i><br/>"
                      "<b>ESTADO:</b> APROBADO PARA DISTRIBUCIÓN EJECUTIVA", cell_body_bold)
        ]
    ]
    t_sign = Table(sign_box, colWidths=[290, 232])
    t_sign.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#94a3b8")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_sign)

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[OK] PDF generado con exito en: {output_pdf_path}")


if __name__ == "__main__":
    out_dir = r"E:\PROYECTOS IA\PRODUCTION READY\100\GITHUB\REPOSITORIOS PARA GITHUB\seguridad GRC"
    out_pdf = os.path.join(out_dir, "Ranking_Categorias_Compania_Estrategia_GRC.pdf")
    logo = r"E:\PROYECTOS IA\PRODUCTION READY\100\GITHUB\REPOSITORIOS PARA GITHUB\seguridad GRC\QUANTIGRADE GRC\assets\Quantigrade.jpg"
    build_ranking_pdf(out_pdf, logo)

