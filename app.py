"""
CoreDefend - Automated Vulnerability Scanner

A professional web-based vulnerability scanner with real-time network
scanning, CVE lookup, and PDF report generation.

Author: CoreDefend Security Team
License: MIT

Usage:
    streamlit run app.py
"""

import streamlit as st
import pandas as pd
from datetime import datetime

# Import local modules
from scanner import (
    NetworkScanner,
    NmapNotInstalledError,
    InsufficientPermissionsError,
    HostUnreachableError,
    NmapScannerError,
    ScanResult
)
from analyzer import (
    VulnerabilityAnalyzer,
    Severity,
    VulnerabilityReport
)
from reporter import ReportGenerator


# Page configuration
st.set_page_config(
    page_title="CoreDefend - Vulnerability Scanner",
    page_icon="CD",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    /* Main header styling */
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E3A5F;
        text-align: center;
        margin-bottom: 0.5rem;
    }

    .sub-header {
        font-size: 1.1rem;
        color: #6B7280;
        text-align: center;
        margin-bottom: 2rem;
    }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }

    /* Severity badges */
    .severity-critical {
        background-color: #DC2626;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.75rem;
    }

    .severity-high {
        background-color: #EA580C;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.75rem;
    }

    .severity-medium {
        background-color: #CA8A04;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.75rem;
    }

    .severity-low {
        background-color: #2563EB;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.75rem;
    }

    .severity-info {
        background-color: #6B7280;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.75rem;
    }

    /* Alert boxes */
    .alert-box {
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        border-left: 4px solid;
    }

    .alert-critical {
        background-color: #FEE2E2;
        border-color: #DC2626;
    }

    .alert-high {
        background-color: #FFEDD5;
        border-color: #EA580C;
    }

    .alert-medium {
        background-color: #FEF3C7;
        border-color: #CA8A04;
    }

    /* Sidebar styling */
    .sidebar .sidebar-content {
        background-color: #F8FAFC;
    }

    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state variables."""
    if 'scan_result' not in st.session_state:
        st.session_state.scan_result = None
    if 'vuln_report' not in st.session_state:
        st.session_state.vuln_report = None
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []
    if 'nmap_available' not in st.session_state:
        st.session_state.nmap_available = None
        st.session_state.nmap_version = None


def check_nmap_installation():
    """Check if Nmap is installed and update session state."""
    if st.session_state.nmap_available is None:
        available, version = NetworkScanner.check_nmap_installed()
        st.session_state.nmap_available = available
        st.session_state.nmap_version = version


def render_sidebar():
    """Render the sidebar with scan configuration options."""
    with st.sidebar:
        st.markdown("## CoreDefend")
        st.markdown("---")

        # Nmap status
        check_nmap_installation()
        if st.session_state.nmap_available:
            st.success(f"{st.session_state.nmap_version}")
        else:
            st.error("Nmap not installed")
            st.markdown("""
            Please install Nmap:
            - **macOS:** `brew install nmap`
            - **Linux:** `sudo apt install nmap`
            - **Windows:** [Download](https://nmap.org/download.html)
            """)
            return None, None

        st.markdown("---")
        st.markdown("### Scan Configuration")

        # Target input
        target = st.text_input(
            "Target",
            placeholder="192.168.1.1 or 192.168.1.0/24",
            help="Enter an IP address, hostname, or CIDR range"
        )

        # Scan type selection
        scan_type = st.selectbox(
            "Scan Type",
            options=["fast", "aggressive"],
            format_func=lambda x: {
                "fast": "Fast Scan (Common Ports)",
                "aggressive": "Aggressive (OS/Version Detection)"
            }.get(x, x),
            help="Fast scan checks common ports. Aggressive scan includes OS and version detection."
        )

        # Advanced options
        with st.expander("Advanced Options"):
            analyze_cve = st.checkbox(
                "Search for CVEs",
                value=True,
                help="Query public CVE databases for known vulnerabilities"
            )

            api_timeout = st.slider(
                "API Timeout (seconds)",
                min_value=5,
                max_value=30,
                value=10,
                help="Timeout for CVE API requests"
            )

        st.markdown("---")

        # Scan button
        scan_clicked = st.button(
            "Start Scan",
            type="primary",
            use_container_width=True,
            disabled=not target
        )

        # Scan history
        if st.session_state.scan_history:
            st.markdown("---")
            st.markdown("### Recent Scans")
            for i, hist in enumerate(st.session_state.scan_history[-5:][::-1]):
                st.caption(f"{hist['time']} - {hist['target']}")

        return (target, scan_type, analyze_cve, api_timeout) if scan_clicked and target else (None, None, None, None)


def perform_scan(target: str, scan_type: str) -> ScanResult:
    """
    Perform network scan with progress indication.

    Args:
        target: Target IP/hostname/range.
        scan_type: Type of scan to perform.

    Returns:
        ScanResult object.
    """
    scanner = NetworkScanner()
    return scanner.scan(target, scan_type)


def analyze_vulnerabilities(scan_result: ScanResult, api_timeout: int) -> VulnerabilityReport:
    """
    Analyze scan results for vulnerabilities.

    Args:
        scan_result: The scan result to analyze.
        api_timeout: Timeout for API requests.

    Returns:
        VulnerabilityReport object.
    """
    analyzer = VulnerabilityAnalyzer(api_timeout=api_timeout)

    # Combine all ports from all hosts
    all_ports = []
    for host in scan_result.hosts:
        all_ports.extend(host.ports)

    return analyzer.generate_report(all_ports)


def render_metrics(scan_result: ScanResult, vuln_report: VulnerabilityReport):
    """Render the metrics dashboard."""
    # Count statistics
    total_hosts = len(scan_result.hosts)
    open_ports = sum(
        len([p for p in h.ports if p.state == "open"])
        for h in scan_result.hosts
    )

    # Count by severity
    severity_counts = {severity: 0 for severity in Severity}
    for alert in vuln_report.port_alerts:
        severity_counts[alert.severity] += 1

    critical_count = severity_counts[Severity.CRITICAL]
    high_count = severity_counts[Severity.HIGH]
    cve_count = len(vuln_report.cve_findings)

    # Display metrics
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric(
            label="Hosts",
            value=total_hosts,
            help="Total number of hosts discovered"
        )

    with col2:
        st.metric(
            label="Open Ports",
            value=open_ports,
            help="Total number of open ports"
        )

    with col3:
        st.metric(
            label="Critical",
            value=critical_count,
            delta=None if critical_count == 0 else "Immediate action required",
            delta_color="inverse" if critical_count > 0 else "off"
        )

    with col4:
        st.metric(
            label="High",
            value=high_count,
            delta=None if high_count == 0 else "Action recommended",
            delta_color="inverse" if high_count > 0 else "off"
        )

    with col5:
        st.metric(
            label="CVEs Found",
            value=cve_count,
            help="Known CVEs matching detected services"
        )


def render_host_results(scan_result: ScanResult):
    """Render the host scan results."""
    st.markdown("### Scan Results")

    for host in scan_result.hosts:
        with st.expander(
            f"{host.ip}" + (f" ({host.hostname})" if host.hostname else ""),
            expanded=True
        ):
            # Host info
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**State:** `{host.state}`")
            with col2:
                if host.os_match:
                    st.markdown(f"**OS:** {host.os_match} ({host.os_accuracy}%)")

            # Ports table
            open_ports = [p for p in host.ports if p.state == "open"]

            if open_ports:
                port_data = []
                for port in open_ports:
                    version = port.version
                    if port.product:
                        version = f"{port.product} {version}".strip()

                    port_data.append({
                        "Port": port.port,
                        "Protocol": port.protocol.upper(),
                        "Service": port.service,
                        "Version": version or "-"
                    })

                df = pd.DataFrame(port_data)
                st.dataframe(
                    df,
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Port": st.column_config.NumberColumn("Port", format="%d"),
                        "Protocol": st.column_config.TextColumn("Protocol"),
                        "Service": st.column_config.TextColumn("Service"),
                        "Version": st.column_config.TextColumn("Version")
                    }
                )
            else:
                st.info("No open ports detected on this host.")


def get_severity_color(severity: Severity) -> str:
    """Get color for severity level."""
    colors = {
        Severity.CRITICAL: "#DC2626",
        Severity.HIGH: "#EA580C",
        Severity.MEDIUM: "#CA8A04",
        Severity.LOW: "#2563EB",
        Severity.INFO: "#6B7280",
        Severity.UNKNOWN: "#9CA3AF"
    }
    return colors.get(severity, "#6B7280")


def render_vulnerability_findings(vuln_report: VulnerabilityReport):
    """Render the vulnerability findings."""
    st.markdown("### Security Findings")

    # Filter significant alerts
    significant_alerts = [
        a for a in vuln_report.port_alerts
        if a.severity not in [Severity.INFO, Severity.UNKNOWN]
    ]

    if not significant_alerts:
        st.success("No significant security issues detected!")
        return

    # Group by severity
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        alerts = [a for a in significant_alerts if a.severity == severity]

        if not alerts:
            continue

        color = get_severity_color(severity)

        for alert in alerts:
            with st.container():
                st.markdown(
                    f"""
                    <div style="
                        background-color: {color}10;
                        border-left: 4px solid {color};
                        padding: 1rem;
                        border-radius: 0 8px 8px 0;
                        margin-bottom: 1rem;
                    ">
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                            <span style="
                                background-color: {color};
                                color: white;
                                padding: 0.25rem 0.75rem;
                                border-radius: 9999px;
                                font-weight: 600;
                                font-size: 0.75rem;
                            ">{severity.value}</span>
                            <strong>Port {alert.port} ({alert.service})</strong>
                        </div>
                        <p style="margin: 0.5rem 0; color: #374151;">{alert.message}</p>
                        <p style="margin: 0; color: #6B7280; font-size: 0.9rem;">
                            <strong>Recommendation:</strong> {alert.recommendation}
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )


def render_cve_findings(vuln_report: VulnerabilityReport):
    """Render CVE findings."""
    if not vuln_report.service_cve_map:
        return

    st.markdown("### CVE Analysis")

    for service, cves in vuln_report.service_cve_map.items():
        with st.expander(f"{service}", expanded=True):
            for cve in cves:
                color = get_severity_color(cve.severity)
                score_badge = f"CVSS: {cve.cvss_score}" if cve.cvss_score else "No Score"

                st.markdown(
                    f"""
                    <div style="
                        border: 1px solid #E5E7EB;
                        border-radius: 8px;
                        padding: 1rem;
                        margin-bottom: 0.5rem;
                    ">
                        <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                            <strong style="color: {color};">{cve.cve_id}</strong>
                            <span style="
                                background-color: {color};
                                color: white;
                                padding: 0.15rem 0.5rem;
                                border-radius: 4px;
                                font-size: 0.7rem;
                            ">{score_badge}</span>
                        </div>
                        <p style="margin: 0.5rem 0; color: #374151; font-size: 0.9rem;">
                            {cve.description[:300]}{'...' if len(cve.description) > 300 else ''}
                        </p>
                        <p style="margin: 0; color: #9CA3AF; font-size: 0.8rem;">
                            Published: {cve.published_date}
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )


def render_download_section(scan_result: ScanResult, vuln_report: VulnerabilityReport):
    """Render the report download section."""
    st.markdown("### Export Report")

    col1, col2 = st.columns(2)

    with col1:
        # Generate PDF
        generator = ReportGenerator()
        pdf_bytes = generator.generate(scan_result, vuln_report)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"coredefend_report_{timestamp}.pdf"

        st.download_button(
            label="Download PDF Report",
            data=pdf_bytes,
            file_name=filename,
            mime="application/pdf",
            use_container_width=True
        )

    with col2:
        # Export as CSV
        all_ports = []
        for host in scan_result.hosts:
            for port in host.ports:
                if port.state == "open":
                    all_ports.append({
                        "Host": host.ip,
                        "Port": port.port,
                        "Protocol": port.protocol,
                        "Service": port.service,
                        "Version": f"{port.product} {port.version}".strip() if port.product else port.version
                    })

        if all_ports:
            df = pd.DataFrame(all_ports)
            csv = df.to_csv(index=False)

            st.download_button(
                label="Download CSV Data",
                data=csv,
                file_name=f"coredefend_ports_{timestamp}.csv",
                mime="text/csv",
                use_container_width=True
            )


def main():
    """Main application entry point."""
    init_session_state()

    # Header
    st.markdown('<h1 class="main-header">CoreDefend</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Automated Vulnerability Scanner</p>',
        unsafe_allow_html=True
    )

    # Sidebar and get scan parameters
    scan_params = render_sidebar()

    if scan_params[0]:  # If scan was triggered
        target, scan_type, analyze_cve, api_timeout = scan_params

        try:
            # Scan phase
            with st.spinner(f"Scanning {target}..."):
                scan_result = perform_scan(target, scan_type)
                st.session_state.scan_result = scan_result

            # Analysis phase
            if analyze_cve:
                with st.spinner("Analyzing vulnerabilities and searching CVEs..."):
                    vuln_report = analyze_vulnerabilities(scan_result, api_timeout)
                    st.session_state.vuln_report = vuln_report
            else:
                # Basic analysis without CVE lookup
                analyzer = VulnerabilityAnalyzer(api_timeout=api_timeout)
                all_ports = []
                for host in scan_result.hosts:
                    all_ports.extend(host.ports)
                vuln_report = VulnerabilityReport(
                    port_alerts=analyzer.analyze_ports(all_ports)
                )
                st.session_state.vuln_report = vuln_report

            # Update history
            st.session_state.scan_history.append({
                "time": datetime.now().strftime("%H:%M"),
                "target": target
            })

            st.success("Scan completed successfully!")

        except NmapNotInstalledError:
            st.error("""
            **Nmap is not installed**

            Please install Nmap to use this scanner:
            - **macOS:** `brew install nmap`
            - **Ubuntu/Debian:** `sudo apt install nmap`
            - **Windows:** Download from [nmap.org](https://nmap.org/download.html)
            """)
        except InsufficientPermissionsError:
            st.error("""
            **Insufficient Permissions**

            This scan type requires root/administrator privileges.
            Try running with `sudo streamlit run app.py`
            """)
        except HostUnreachableError as e:
            st.warning(f"**Host Unreachable:** {e}")
        except NmapScannerError as e:
            st.error(f"**Scan Error:** {e}")
        except ValueError as e:
            st.error(f"**Invalid Input:** {e}")

    # Display results if available
    if st.session_state.scan_result and st.session_state.vuln_report:
        scan_result = st.session_state.scan_result
        vuln_report = st.session_state.vuln_report

        st.markdown("---")

        # Metrics dashboard
        render_metrics(scan_result, vuln_report)

        st.markdown("---")

        # Create tabs for different views
        tab1, tab2, tab3, tab4 = st.tabs([
            "Scan Results",
            "Security Findings",
            "CVE Analysis",
            "Export"
        ])

        with tab1:
            render_host_results(scan_result)

        with tab2:
            render_vulnerability_findings(vuln_report)

        with tab3:
            render_cve_findings(vuln_report)

        with tab4:
            render_download_section(scan_result, vuln_report)

    else:
        # Welcome message when no scan has been performed
        st.markdown("---")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown("""
            #### Network Scanning
            Discover hosts and open ports using Nmap's
            powerful scanning engine.
            """)

        with col2:
            st.markdown("""
            #### Vulnerability Analysis
            Identify security risks and query CVE
            databases for known vulnerabilities.
            """)

        with col3:
            st.markdown("""
            #### Professional Reports
            Generate detailed PDF reports for
            documentation and compliance.
            """)

        st.markdown("---")
        st.info("Enter a target IP address or range in the sidebar to begin scanning.")


if __name__ == "__main__":
    main()
