import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(scan_data: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=10
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#0EA5E9'),
        spaceBefore=15,
        spaceAfter=10
    )

    normal_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1E293B')
    )

    story = []

    # Title & Subtitle
    story.append(Paragraph("Website Vulnerability Security Report", title_style))
    created_at = scan_data.get("created_at") or datetime.now().isoformat()
    story.append(Paragraph(f"Target URL: <b>{scan_data.get('url')}</b> | Generated: {created_at}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=15))

    # Summary Metrics Table
    risk_level = scan_data.get("risk_level", "LOW").upper()
    risk_color = colors.HexColor('#EF4444') if risk_level == "HIGH" else (colors.HexColor('#F59E0B') if risk_level == "MEDIUM" else colors.HexColor('#10B981'))

    crawl_res = scan_data.get("crawl_results", {})
    findings = scan_data.get("findings", {})

    sql_count = len(findings.get("sql", []))
    xss_count = len(findings.get("xss", []))
    header_missing_count = len(findings.get("headers", {}).get("missing", []))
    cookie_insecure_count = len(findings.get("cookies", {}).get("insecure", []))
    total_vulnerabilities = sql_count + xss_count + header_missing_count + cookie_insecure_count

    summary_data = [
        [Paragraph("<b>Overall Risk Level</b>", normal_style), Paragraph(f"<b><font color='{risk_color.hexval()}'>{risk_level}</font></b>", normal_style)],
        [Paragraph("<b>Target Domain</b>", normal_style), Paragraph(str(scan_data.get("url")), normal_style)],
        [Paragraph("<b>Scanned Pages Count</b>", normal_style), Paragraph(str(crawl_res.get("pages_crawled", 0)), normal_style)],
        [Paragraph("<b>Discovered Forms</b>", normal_style), Paragraph(str(len(crawl_res.get("forms", []))), normal_style)],
        [Paragraph("<b>Identified Security Issues</b>", normal_style), Paragraph(str(total_vulnerabilities), normal_style)],
    ]

    t_summary = Table(summary_data, colWidths=[180, 360])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 15))

    # 1. SQL Injection Section
    story.append(Paragraph("1. SQL Injection Findings", h2_style))
    if sql_count > 0:
        sql_table_data = [["Severity", "URL / Endpoint", "Parameter", "Evidence / DB"]]
        for item in findings.get("sql", []):
            sql_table_data.append([
                Paragraph(f"<font color='#EF4444'><b>{item.get('severity', 'HIGH')}</b></font>", normal_style),
                Paragraph(str(item.get("url")), normal_style),
                Paragraph(str(item.get("parameter")), normal_style),
                Paragraph(str(item.get("evidence", item.get("database_type", "SQL Error"))), normal_style)
            ])
        t_sql = Table(sql_table_data, colWidths=[65, 200, 95, 180])
        t_sql.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t_sql)
    else:
        story.append(Paragraph("No SQL Injection vulnerabilities detected.", normal_style))

    story.append(Spacer(1, 10))

    # 2. Reflected XSS Section
    story.append(Paragraph("2. Reflected XSS Findings", h2_style))
    if xss_count > 0:
        xss_table_data = [["Severity", "URL / Endpoint", "Parameter", "Payload"]]
        for item in findings.get("xss", []):
            xss_table_data.append([
                Paragraph(f"<font color='#F59E0B'><b>{item.get('severity', 'MEDIUM')}</b></font>", normal_style),
                Paragraph(str(item.get("url")), normal_style),
                Paragraph(str(item.get("parameter")), normal_style),
                Paragraph(str(item.get("payload")), normal_style)
            ])
        t_xss = Table(xss_table_data, colWidths=[65, 200, 95, 180])
        t_xss.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t_xss)
    else:
        story.append(Paragraph("No Reflected XSS vulnerabilities detected.", normal_style))

    story.append(Spacer(1, 10))

    # 3. Security Headers Section
    story.append(Paragraph("3. Security Response Headers", h2_style))
    missing_headers = findings.get("headers", {}).get("missing", [])
    if missing_headers:
        header_table_data = [["Header Name", "Risk Impact", "Recommendation"]]
        for item in missing_headers:
            header_table_data.append([
                Paragraph(f"<b>{item.get('header')}</b>", normal_style),
                Paragraph(str(item.get("risk")), normal_style),
                Paragraph(str(item.get("recommendation")), normal_style)
            ])
        t_headers = Table(header_table_data, colWidths=[160, 90, 290])
        t_headers.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t_headers)
    else:
        story.append(Paragraph("All evaluated security headers are present.", normal_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
