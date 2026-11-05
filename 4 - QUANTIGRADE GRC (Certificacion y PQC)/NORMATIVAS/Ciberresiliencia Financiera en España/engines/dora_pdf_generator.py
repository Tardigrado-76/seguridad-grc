import datetime
import logging
from pathlib import Path

from fpdf import FPDF

logger = logging.getLogger(__name__)

DEFAULT_REPORTS_DIR = Path(__file__).parent / "REPORTS"


class DORAPDFReport(FPDF):
    def header(self) -> None:
        self.set_font("Arial", "B", 15)
        self.cell(0, 10, "DORA Compliance & Resiliency Report", 0, 1, "C")
        self.set_font("Arial", "I", 10)
        self.cell(
            0,
            10,
            f"Generado el: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
            0,
            1,
            "C",
        )
        self.ln(10)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")


def generate_report(
    project_path: str, errors: list[str], output_path: str | None = None
) -> str:
    reports_dir = DEFAULT_REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)

    if output_path is None or output_path == "DORA_Report.pdf":
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
        target_file = reports_dir / f"DORA_Report_{timestamp}.pdf"
    else:
        p = Path(output_path)
        target_file = p if p.is_absolute() else (reports_dir / p.name)

    pdf = DORAPDFReport()
    pdf.add_page()

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Target Project:", 0, 1)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 10, str(project_path), 0, 1)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Audit Findings (Code Doctor / DORA Rules):", 0, 1)
    pdf.set_font("Arial", "", 10)

    if not errors:
        pdf.cell(0, 10, "No issues found. 100% compliant.", 0, 1)
    else:
        for err in errors:
            pdf.multi_cell(0, 8, f"- {err}")

    pdf.output(str(target_file))
    logger.info(f"PDF report generated at {target_file}")
    return str(target_file)
