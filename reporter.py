"""
CoreDefend - Report Generator Module

This module provides PDF report generation capabilities for
vulnerability scan results using ReportLab.

Author: Mattia Calasso
License: MIT
"""

import io
from datetime import datetime
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

from analyzer import Severity, PortAlert, CVEInfo, VulnerabilityReport
from scanner import ScanResult, HostInfo


# Color scheme
COLORS = {
    Severity.CRITICAL: colors.HexColor("#DC2626"),  # Red
    Severity.HIGH: colors.HexColor("#EA580C"),      # Orange
    Severity.MEDIUM: colors.HexColor("#CA8A04"),    # Yellow
    Severity.LOW: colors.HexColor("#2563EB"),       # Blue
    Severity.INFO: colors.HexColor("#6B7280"),      # Gray
    Severity.UNKNOWN: colors.HexColor("#9CA3AF"),   # Light Gray
}

HEADER_COLOR = colors.HexColor("#1E3A5F")
ACCENT_COLOR = colors.HexColor("#3B82F6")


class ReportGenerator:
    """
    PDF report generator for vulnerability scan results.

    Creates professional, formatted PDF reports containing:
    - Executive summary
    - Scan statistics
    - Detailed findings
    - Recommendations

    Attributes:
        page_size: Page size tuple (default: A4).
        styles: ReportLab stylesheet.

    Example:
        >>> generator = ReportGenerator()
        >>> pdf_bytes = generator.generate(scan_result, vuln_report)
        >>> with open("report.pdf", "wb") as f:
        ...     f.write(pdf_bytes)
    """

    def __init__(self, page_size: tuple = A4) -> None:
        """
        Initialize the ReportGenerator.

        Args:
            page_size: Page size tuple (default: A4). Use letter for US format.
        """
        self.page_size = page_size
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _add_style_if_not_exists(self, style: ParagraphStyle) -> None:
        """Add a style only if it doesn't already exist."""
        if style.name not in self.styles.byName:
            self.styles.add(style)

    def _setup_custom_styles(self) -> None:
        """Set up custom paragraph styles for the report."""
        # Title style
        self._add_style_if_not_exists(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            textColor=HEADER_COLOR,
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Subtitle style
        self._add_style_if_not_exists(ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor("#6B7280"),
            spaceAfter=20,
            alignment=TA_CENTER
        ))

        # Section header style
        self._add_style_if_not_exists(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=HEADER_COLOR,
            spaceBefore=20,
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))

        # Subsection header style
        self._add_style_if_not_exists(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=HEADER_COLOR,
            spaceBefore=15,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))

        # Body text style - override existing BodyText
        self.styles['BodyText'].fontSize = 10
        self.styles['BodyText'].textColor = colors.HexColor("#374151")
        self.styles['BodyText'].spaceAfter = 8
        self.styles['BodyText'].alignment = TA_JUSTIFY
        self.styles['BodyText'].leading = 14

        # Alert text styles for each severity
        for severity, color in COLORS.items():
            self._add_style_if_not_exists(ParagraphStyle(
                name=f'Alert{severity.value}',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=color,
                fontName='Helvetica-Bold'
            ))

    def _create_header(self, scan_result: ScanResult) -> list:
        """
        Create the report header section.

        Args:
            scan_result: The scan result data.

        Returns:
            List of flowable elements for the header.
        """
        elements = []

        # Title
        elements.append(Paragraph("CoreDefend", self.styles['ReportTitle']))
        elements.append(Paragraph(
            "Vulnerability Assessment Report",
            self.styles['ReportSubtitle']
        ))

        # Horizontal rule
        elements.append(HRFlowable(
            width="100%",
            thickness=2,
            color=ACCENT_COLOR,
            spaceAfter=20
        ))

        # Report metadata
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metadata = [
            ["Report Generated:", scan_date],
            ["Target:", scan_result.target],
            ["Scan Type:", scan_result.scan_type.upper()],
            ["Command:", scan_result.command_line[:70] + "..." if len(scan_result.command_line) > 70 else scan_result.command_line]
        ]

        meta_table = Table(metadata, colWidths=[2*inch, 4.5*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), HEADER_COLOR),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor("#374151")),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))

        elements.append(meta_table)
        elements.append(Spacer(1, 20))

        return elements

    def _create_executive_summary(
        self,
        scan_result: ScanResult,
        vuln_report: VulnerabilityReport
    ) -> list:
        """
        Create the executive summary section.

        Args:
            scan_result: The scan result data.
            vuln_report: The vulnerability report data.

        Returns:
            List of flowable elements for the executive summary.
        """
        elements = []

        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))

        # Calculate statistics
        total_hosts = len(scan_result.hosts)
        total_ports = sum(len(h.ports) for h in scan_result.hosts)
        open_ports = sum(
            len([p for p in h.ports if p.state == "open"])
            for h in scan_result.hosts
        )

        # Count alerts by severity
        severity_counts = {severity: 0 for severity in Severity}
        for alert in vuln_report.port_alerts:
            severity_counts[alert.severity] += 1

        critical_count = severity_counts[Severity.CRITICAL]
        high_count = severity_counts[Severity.HIGH]
        medium_count = severity_counts[Severity.MEDIUM]

        # Summary text
        risk_level = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "MEDIUM" if medium_count > 0 else "LOW"

        summary_text = f"""
        This vulnerability assessment was conducted on <b>{scan_result.target}</b>.
        The scan identified <b>{total_hosts}</b> host(s) with <b>{open_ports}</b> open port(s).
        <br/><br/>
        <b>Overall Risk Level: {risk_level}</b>
        <br/><br/>
        The assessment found:
        """
        elements.append(Paragraph(summary_text, self.styles['BodyText']))

        # Findings summary table
        findings = [
            ["Severity", "Count", "Description"],
            ["CRITICAL", str(critical_count), "Immediate action required"],
            ["HIGH", str(high_count), "Address within 24-48 hours"],
            ["MEDIUM", str(medium_count), "Address within 1 week"],
            ["LOW", str(severity_counts[Severity.LOW]), "Address during regular maintenance"],
            ["INFO", str(severity_counts[Severity.INFO]), "For informational purposes"],
        ]

        findings_table = Table(findings, colWidths=[1.5*inch, 1*inch, 3.5*inch])
        findings_table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), HEADER_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),

            # Data rows
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 1), (1, -1), 'CENTER'),
            ('ALIGN', (2, 1), (2, -1), 'LEFT'),

            # Severity colors
            ('TEXTCOLOR', (0, 1), (0, 1), COLORS[Severity.CRITICAL]),
            ('TEXTCOLOR', (0, 2), (0, 2), COLORS[Severity.HIGH]),
            ('TEXTCOLOR', (0, 3), (0, 3), COLORS[Severity.MEDIUM]),
            ('TEXTCOLOR', (0, 4), (0, 4), COLORS[Severity.LOW]),
            ('TEXTCOLOR', (0, 5), (0, 5), COLORS[Severity.INFO]),

            # Grid
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),

            # Padding
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(findings_table)
        elements.append(Spacer(1, 20))

        return elements

    def _create_host_details(self, scan_result: ScanResult) -> list:
        """
        Create the host details section.

        Args:
            scan_result: The scan result data.

        Returns:
            List of flowable elements for host details.
        """
        elements = []

        elements.append(Paragraph("Scan Results", self.styles['SectionHeader']))

        for host in scan_result.hosts:
            # Host header
            host_title = f"Host: {host.ip}"
            if host.hostname:
                host_title += f" ({host.hostname})"
            elements.append(Paragraph(host_title, self.styles['SubsectionHeader']))

            # Host info
            host_info = f"<b>State:</b> {host.state}"
            if host.os_match:
                host_info += f" | <b>OS:</b> {host.os_match} ({host.os_accuracy}% confidence)"
            elements.append(Paragraph(host_info, self.styles['BodyText']))

            # Ports table
            if host.ports:
                open_ports = [p for p in host.ports if p.state == "open"]

                if open_ports:
                    port_data = [["Port", "Protocol", "State", "Service", "Version"]]

                    for port in open_ports:
                        version = port.version
                        if port.product:
                            version = f"{port.product} {version}".strip()
                        if port.extra_info:
                            version += f" ({port.extra_info})"

                        port_data.append([
                            str(port.port),
                            port.protocol.upper(),
                            port.state.upper(),
                            port.service,
                            version[:40] + "..." if len(version) > 40 else version
                        ])

                    port_table = Table(
                        port_data,
                        colWidths=[0.8*inch, 0.8*inch, 0.8*inch, 1.2*inch, 2.4*inch]
                    )
                    port_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), ACCENT_COLOR),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ]))

                    elements.append(port_table)
                else:
                    elements.append(Paragraph(
                        "No open ports detected.",
                        self.styles['BodyText']
                    ))
            else:
                elements.append(Paragraph(
                    "No port information available.",
                    self.styles['BodyText']
                ))

            elements.append(Spacer(1, 15))

        return elements

    def _create_vulnerability_findings(self, vuln_report: VulnerabilityReport) -> list:
        """
        Create the vulnerability findings section.

        Args:
            vuln_report: The vulnerability report data.

        Returns:
            List of flowable elements for vulnerability findings.
        """
        elements = []

        elements.append(Paragraph("Security Findings", self.styles['SectionHeader']))

        if not vuln_report.port_alerts:
            elements.append(Paragraph(
                "No significant security findings identified.",
                self.styles['BodyText']
            ))
            return elements

        # Filter out INFO level alerts for the main findings
        significant_alerts = [
            a for a in vuln_report.port_alerts
            if a.severity not in [Severity.INFO, Severity.UNKNOWN]
        ]

        if not significant_alerts:
            elements.append(Paragraph(
                "No significant security findings. Only informational items detected.",
                self.styles['BodyText']
            ))
            return elements

        for i, alert in enumerate(significant_alerts, 1):
            severity_color = COLORS.get(alert.severity, colors.gray)

            # Finding header
            finding_title = f"Finding #{i}: Port {alert.port} ({alert.service})"
            elements.append(Paragraph(finding_title, self.styles['SubsectionHeader']))

            # Severity badge
            severity_text = f"<font color='{severity_color}'><b>[{alert.severity.value}]</b></font>"
            elements.append(Paragraph(severity_text, self.styles['BodyText']))

            # Description
            elements.append(Paragraph(
                f"<b>Issue:</b> {alert.message}",
                self.styles['BodyText']
            ))

            # Recommendation
            elements.append(Paragraph(
                f"<b>Recommendation:</b> {alert.recommendation}",
                self.styles['BodyText']
            ))

            elements.append(Spacer(1, 10))

        return elements

    def _create_cve_section(self, vuln_report: VulnerabilityReport) -> list:
        """
        Create the CVE findings section.

        Args:
            vuln_report: The vulnerability report data.

        Returns:
            List of flowable elements for CVE findings.
        """
        elements = []

        if not vuln_report.service_cve_map:
            return elements

        elements.append(Paragraph("CVE Analysis", self.styles['SectionHeader']))

        for service, cves in vuln_report.service_cve_map.items():
            elements.append(Paragraph(
                f"Service: {service}",
                self.styles['SubsectionHeader']
            ))

            for cve in cves:
                severity_color = COLORS.get(cve.severity, colors.gray)

                # CVE ID and score
                score_text = f"(CVSS: {cve.cvss_score})" if cve.cvss_score else ""
                cve_header = f"<font color='{severity_color}'><b>{cve.cve_id}</b></font> {score_text}"
                elements.append(Paragraph(cve_header, self.styles['BodyText']))

                # Description
                elements.append(Paragraph(
                    cve.description,
                    self.styles['BodyText']
                ))

                # Published date
                elements.append(Paragraph(
                    f"<i>Published: {cve.published_date}</i>",
                    self.styles['BodyText']
                ))

                elements.append(Spacer(1, 8))

        return elements

    def _create_footer(self) -> list:
        """
        Create the report footer section.

        Returns:
            List of flowable elements for the footer.
        """
        elements = []

        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor("#E5E7EB"),
            spaceBefore=30,
            spaceAfter=20
        ))

        disclaimer = """
        <b>Disclaimer:</b> This report is generated automatically based on network scanning
        and public vulnerability databases. It should be used as a starting point for
        security assessment and not as a definitive security audit. Always verify findings
        manually and consult with security professionals for critical systems.
        """
        elements.append(Paragraph(disclaimer, self.styles['BodyText']))

        elements.append(Spacer(1, 20))

        footer_text = f"""
        <para alignment="center">
        <font size="9" color="#6B7280">
        Generated by CoreDefend Vulnerability Scanner<br/>
        Report Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br/>
        © {datetime.now().year} CoreDefend Security
        </font>
        </para>
        """
        elements.append(Paragraph(footer_text, self.styles['Normal']))

        return elements

    def generate(
        self,
        scan_result: ScanResult,
        vuln_report: VulnerabilityReport,
        filename: Optional[str] = None
    ) -> bytes:
        """
        Generate a complete PDF vulnerability report.

        Args:
            scan_result: The scan result data from NetworkScanner.
            vuln_report: The vulnerability report from VulnerabilityAnalyzer.
            filename: Optional filename to save the PDF to.

        Returns:
            PDF content as bytes.

        Example:
            >>> generator = ReportGenerator()
            >>> pdf_bytes = generator.generate(scan_result, vuln_report)
            >>> with open("report.pdf", "wb") as f:
            ...     f.write(pdf_bytes)
        """
        # Create buffer for PDF
        buffer = io.BytesIO()

        # Create document
        doc = SimpleDocTemplate(
            buffer,
            pagesize=self.page_size,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )

        # Build content
        elements = []

        # Add sections
        elements.extend(self._create_header(scan_result))
        elements.extend(self._create_executive_summary(scan_result, vuln_report))
        elements.extend(self._create_host_details(scan_result))
        elements.extend(self._create_vulnerability_findings(vuln_report))
        elements.extend(self._create_cve_section(vuln_report))
        elements.extend(self._create_footer())

        # Build PDF
        doc.build(elements)

        # Get PDF content
        pdf_content = buffer.getvalue()
        buffer.close()

        # Optionally save to file
        if filename:
            with open(filename, 'wb') as f:
                f.write(pdf_content)

        return pdf_content

