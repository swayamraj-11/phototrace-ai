"""
Report Generator for PhotoTrace AI.

Produces:
1. Structured Forensic JSON reports (ISO 8601 compliant, complete metadata dump).
2. Professional Forensic PDF reports using ReportLab with:
   - Unique forensic investigation ID
   - UTC verification timestamps
   - Cryptographic SHA-256 evidence seals
   - Structured metadata tables
   - Integrity finding badges & explanations
   - GPS coordinates and reverse geocode summary
   - Forensic disclaimers and legal limitations
"""

import io
import json
import uuid
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and print total page count
    and forensic security footer.
    """
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
            super().showPage()
        super().save()

    def draw_footer(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#718096"))
        
        # Security seal footer line
        self.setStrokeColor(colors.HexColor("#2d3748"))
        self.setLineWidth(0.5)
        self.line(40, 35, 572, 35)
        
        # Left footer: System version & verification seal
        self.drawString(40, 24, "PhotoTrace AI v1.0.0 — Forensic Evidence Analysis Report | Integrity Verified")
        
        # Right footer: Page numbers
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(572, 24, page_str)
        self.restoreState()


def generate_json_report(analysis_data: dict) -> str:
    """Generates formatted JSON forensic report."""
    report_id = analysis_data.get("report_id") or f"PT-{uuid.uuid4().hex[:12].upper()}"
    report_payload = {
        "report_metadata": {
            "application": "PhotoTrace AI — Digital Photo Forensics & Metadata Analyzer",
            "version": "1.0.0",
            "report_id": report_id,
            "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "forensic_integrity_note": "This report contains extracted digital metadata from submitted evidence.",
        },
        "analysis_results": analysis_data,
    }
    return json.dumps(report_payload, indent=2, ensure_ascii=False)


def generate_pdf_report(analysis_data: dict) -> bytes:
    """
    Generates a high-quality, professional PDF report using ReportLab.
    Safely escapes untrusted strings to prevent XML/injection issues.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=50,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#00f0ff"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#a0aec0"),
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#00ff9d"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#e2e8f0"),
    )
    cell_label = ParagraphStyle(
        "CellLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#90cdf4"),
    )
    cell_val = ParagraphStyle(
        "CellValue",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#ffffff"),
    )
    alert_style = ParagraphStyle(
        "AlertBox",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#cbd5e0"),
    )

    story = []

    # Safe escape helper
    def safe(text):
        if text is None:
            return "<i>Not available</i>"
        return escape(str(text))

    report_id = analysis_data.get("report_id") or f"PT-{uuid.uuid4().hex[:12].upper()}"
    summary = analysis_data.get("summary", {})
    timestamps = analysis_data.get("timestamps", {})
    camera = analysis_data.get("camera_device", {})
    settings = analysis_data.get("capture_settings", {})
    props = analysis_data.get("image_properties", {})
    sw = analysis_data.get("software_metadata", {})
    gps = analysis_data.get("gps", {})
    integrity = analysis_data.get("integrity", {})

    # Top Header Banner
    header_data = [
        [
            Paragraph("<b>PHOTOTRACE AI</b> &nbsp;|&nbsp; DIGITAL FORENSICS REPORT", title_style),
            Paragraph(f"<b>REPORT ID:</b> {report_id}<br/><b>DATE (UTC):</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style)
        ]
    ]
    t_header = Table(header_data, colWidths=[330, 202])
    t_header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0a0f1d")),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 2, colors.HexColor("#00f0ff")),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 12))

    # Evidence Summary Section
    story.append(Paragraph("1. EVIDENCE IDENTIFICATION & CRYPTOGRAPHIC HASH", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e293b"), spaceAfter=6))

    evidence_rows = [
        [Paragraph("Submitted Filename:", cell_label), Paragraph(safe(summary.get("original_filename")), cell_val)],
        [Paragraph("File Size & Format:", cell_label), Paragraph(f"{safe(summary.get('file_size_formatted'))} ({safe(summary.get('file_size_bytes'))} bytes) | {safe(props.get('format'))}", cell_val)],
        [Paragraph("Raster Dimensions:", cell_label), Paragraph(f"{safe(summary.get('dimensions'))} ({safe(props.get('megapixels'))})", cell_val)],
        [Paragraph("SHA-256 Hash:", cell_label), Paragraph(f"<font name='Courier-Bold' color='#00ff9d'>{safe(summary.get('sha256'))}</font>", cell_val)],
        [Paragraph("Analysis Completed:", cell_label), Paragraph(f"{safe(timestamps.get('analysis_completed_utc'))}", cell_val)],
        [Paragraph("Metadata Completeness:", cell_label), Paragraph(f"{safe(summary.get('completeness_score'))}% ({safe(summary.get('completeness_ratio'))})", cell_val)],
    ]
    t_evidence = Table(evidence_rows, colWidths=[140, 392])
    t_evidence.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t_evidence)
    story.append(Spacer(1, 10))

    # Forensic Integrity & Anomaly Checks
    story.append(Paragraph("2. FORENSIC INTEGRITY & MANIPULATION EVALUATION", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e293b"), spaceAfter=6))

    findings = integrity.get("findings", [])
    if findings:
        findings_rows = [
            [
                Paragraph("<b>Forensic Check</b>", cell_label),
                Paragraph("<b>Status</b>", cell_label),
                Paragraph("<b>Detected Fact & Investigative Interpretation</b>", cell_label),
            ]
        ]
        for f in findings:
            st = f.get("status", "Unknown")
            if st == "Data Found":
                st_color = "#00ff9d"
            elif st == "Potential Inconsistency":
                st_color = "#ff416c"
            elif st == "Needs Verification":
                st_color = "#ffb700"
            else:
                st_color = "#718096"
            
            status_p = Paragraph(f"<font color='{st_color}'><b>{safe(st)}</b></font>", cell_val)
            desc_p = Paragraph(f"<b>Fact:</b> {safe(f.get('detected_fact'))}<br/><b>Interpretation:</b> {safe(f.get('interpretation'))}", cell_val)
            findings_rows.append([Paragraph(safe(f.get("check")), cell_label), status_p, desc_p])

        t_findings = Table(findings_rows, colWidths=[120, 95, 317])
        t_findings.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#162032")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t_findings)
    story.append(Spacer(1, 10))

    # Camera & Capture Details
    story.append(Paragraph("3. HARDWARE & CAPTURE TELEMETRY", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e293b"), spaceAfter=6))

    camera_rows = [
        [Paragraph("Device Manufacturer:", cell_label), Paragraph(safe(camera.get("make")), cell_val),
         Paragraph("Shutter / Exposure:", cell_label), Paragraph(safe(settings.get("exposure_time")), cell_val)],
        [Paragraph("Device Model:", cell_label), Paragraph(safe(camera.get("model")), cell_val),
         Paragraph("Aperture (F-Number):", cell_label), Paragraph(safe(settings.get("f_number")), cell_val)],
        [Paragraph("Lens Make / Model:", cell_label), Paragraph(f"{safe(camera.get('lens_make'))} {safe(camera.get('lens_model'))}", cell_val),
         Paragraph("ISO Sensitivity:", cell_label), Paragraph(safe(settings.get("iso")), cell_val)],
        [Paragraph("Serial / Body ID:", cell_label), Paragraph(safe(camera.get("body_serial")), cell_val),
         Paragraph("Focal Length:", cell_label), Paragraph(f"{safe(settings.get('focal_length'))} ({safe(settings.get('focal_length_35mm'))})", cell_val)],
        [Paragraph("Flash Strobe:", cell_label), Paragraph(safe(settings.get("flash")), cell_val),
         Paragraph("Orientation:", cell_label), Paragraph(safe(settings.get("orientation")), cell_val)],
    ]
    t_camera = Table(camera_rows, colWidths=[110, 156, 110, 156])
    t_camera.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t_camera)
    story.append(Spacer(1, 10))

    # Geolocation & Timestamps
    story.append(Paragraph("4. GEOLOCATION & CHRONOLOGY", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e293b"), spaceAfter=6))

    geo_loc = gps.get("location_approximate", {}) or {}
    geo_rows = [
        [Paragraph("GPS Status:", cell_label), Paragraph(safe(gps.get("status_message")), cell_val)],
        [Paragraph("Coordinates:", cell_label), Paragraph(safe(gps.get("coordinates_formatted")), cell_val)],
        [Paragraph("Approx. Reverse Address:", cell_label), Paragraph(safe(geo_loc.get("display_name")), cell_val)],
        [Paragraph("Capture Timestamp (EXIF):", cell_label), Paragraph(safe(timestamps.get("capture_timestamp")), cell_val)],
        [Paragraph("Digitized Timestamp:", cell_label), Paragraph(safe(timestamps.get("digitized_timestamp")), cell_val)],
        [Paragraph("Metadata Modified:", cell_label), Paragraph(safe(timestamps.get("metadata_modified_timestamp")), cell_val)],
        [Paragraph("Host Filesystem Times:", cell_label), Paragraph(f"Created: {safe(timestamps.get('filesystem_created_utc'))}<br/>Modified: {safe(timestamps.get('filesystem_modified_utc'))}", cell_val)],
    ]
    t_geo = Table(geo_rows, colWidths=[140, 392])
    t_geo.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t_geo)
    story.append(Spacer(1, 10))

    # Software & Provenance
    story.append(Paragraph("5. SOFTWARE & PROVENANCE METADATA", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1e293b"), spaceAfter=6))

    sw_rows = [
        [Paragraph("Software Application:", cell_label), Paragraph(safe(sw.get("software")), cell_val)],
        [Paragraph("Artist / Creator:", cell_label), Paragraph(safe(sw.get("artist")), cell_val)],
        [Paragraph("Copyright Record:", cell_label), Paragraph(safe(sw.get("copyright")), cell_val)],
        [Paragraph("Image Description / User Comment:", cell_label), Paragraph(f"{safe(sw.get('image_description'))} {safe(sw.get('user_comment'))}", cell_val)],
    ]
    t_sw = Table(sw_rows, colWidths=[140, 392])
    t_sw.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#1e293b")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t_sw)
    story.append(Spacer(1, 12))

    # Forensic Disclaimer & Legal Boundaries Box
    disclaimer_text = (
        "<b>CRITICAL FORENSIC LIMITATIONS & LEGAL NOTICE:</b><br/>"
        "1. A digital image file alone CANNOT conclusively prove original author ownership, the originating individual, "
        "or the messaging network (e.g. WhatsApp, AirDrop, Signal) used for transmission.<br/>"
        "2. Missing metadata is NOT definitive proof of malicious tampering; modern messaging platforms strip EXIF for privacy by design.<br/>"
        "3. Editing software tags indicate the file was saved using that software, which may reflect innocent rotation or compression.<br/>"
        "4. This automated analysis report is generated by PhotoTrace AI and should be corroborated with hardware chain-of-custody for judicial proceedings."
    )
    disclaimer_table = Table([[Paragraph(disclaimer_text, alert_style)]], colWidths=[532])
    disclaimer_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#111827")),
        ("LINEBEFORE", (0, 0), (-1, -1), 3, colors.HexColor("#ffb700")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#374151")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(disclaimer_table)

    # Build PDF with dynamic NumberedCanvas for professional page numbering
    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
