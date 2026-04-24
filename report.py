from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
import json
from datetime import datetime

def generate_pdf(data, target):
    doc = SimpleDocTemplate("scan_report.pdf")

    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("Vulnerability Scan Report", styles['Title']))
    elements.append(Spacer(1, 10))

    # Info
    elements.append(Paragraph(f"Target: {target}", styles['Normal']))
    elements.append(Paragraph(f"Date: {datetime.now()}", styles['Normal']))
    elements.append(Spacer(1, 20))

    # Table Data
    table_data = [["Vulnerability", "Result", "Severity"]]

    for item in data:
        table_data.append([
            item.get("name", ""),
            item.get("result", ""),
            item.get("severity", "")
        ])

    table = Table(table_data)

    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.black),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),

        ('GRID', (0,0), (-1,-1), 1, colors.gray),

        ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke)
    ]))

    elements.append(table)

    doc.build(elements)