"""
CoreDefend - Vulnerability Analyzer Module

This module provides vulnerability analysis capabilities including
CVE lookup via public APIs and critical port identification.

Author: CoreDefend Security Team
License: MIT
"""

import re
import requests
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Enumeration of vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


@dataclass
class CVEInfo:
    """Data class representing CVE (Common Vulnerabilities and Exposures) information."""
    cve_id: str
    description: str
    severity: Severity
    cvss_score: Optional[float]
    published_date: str
    references: list[str] = field(default_factory=list)
    relevance_score: float = 0.0  # How relevant this CVE is to the search


@dataclass
class PortAlert:
    """Data class representing a security alert for a port."""
    port: int
    service: str
    severity: Severity
    message: str
    recommendation: str


@dataclass
class VulnerabilityReport:
    """Data class representing the complete vulnerability analysis report."""
    port_alerts: list[PortAlert] = field(default_factory=list)
    cve_findings: list[CVEInfo] = field(default_factory=list)
    service_cve_map: dict = field(default_factory=dict)  # Maps service to list of CVEs


# ============================================================================
# CVE FILTERING CONFIGURATION
# ============================================================================

# Minimum year for CVE results (filter out ancient vulnerabilities)
MIN_CVE_YEAR = 2015

# Generic service names that should NOT trigger CVE searches alone
# These need a specific version to be searchable
GENERIC_SERVICES_BLACKLIST = {
    "http", "https", "ssh", "ftp", "smtp", "dns", "domain",
    "pop3", "imap", "ldap", "snmp", "ntp", "telnet", "mysql",
    "postgresql", "mongodb", "redis", "smb", "netbios", "msrpc",
    "upnp", "ssdp", "rtsp", "sip", "vnc", "rdp", "tcpwrapped",
    "unknown", "filtered", "http-proxy", "ssl", "tls"
}

# Obsolete/legacy systems to exclude from CVE results
OBSOLETE_SYSTEMS_PATTERNS = [
    r"windows\s*(95|98|me|nt|2000|xp|vista)",
    r"windows\s*server\s*(2000|2003)",
    r"solaris\s*[2-9](\.[0-9])?",
    r"sunos\s*[4-5]",
    r"hp[\s-]?(ux|apollo)",
    r"irix",
    r"aix\s*[1-4]",
    r"os/2",
    r"netware",
    r"vms",
    r"domain/os",
    r"nextstep",
    r"beos",
    r"sco\s*unix",
    r"ultrix",
    r"osf/1",
    r"tru64",
]

# Minimum version pattern - requires at least product + version number
VERSION_PATTERN = re.compile(r'^(.+?)\s+(\d+\.[\d\.]+)', re.IGNORECASE)

# ============================================================================
# CRITICAL PORTS CONFIGURATION
# ============================================================================

CRITICAL_PORTS = {
    21: {
        "service": "FTP",
        "severity": Severity.HIGH,
        "message": "FTP (File Transfer Protocol) transmits credentials in plaintext",
        "recommendation": "Replace with SFTP or FTPS. If FTP is required, ensure it's isolated and uses strong authentication."
    },
    22: {
        "service": "SSH",
        "severity": Severity.MEDIUM,
        "message": "SSH port is exposed. Ensure strong authentication is configured.",
        "recommendation": "Use key-based authentication, disable root login, implement fail2ban, consider changing default port."
    },
    23: {
        "service": "Telnet",
        "severity": Severity.CRITICAL,
        "message": "Telnet transmits all data including passwords in plaintext",
        "recommendation": "IMMEDIATELY disable Telnet and replace with SSH. Telnet should never be used on production systems."
    },
    25: {
        "service": "SMTP",
        "severity": Severity.MEDIUM,
        "message": "SMTP port exposed. May be vulnerable to spam relay attacks.",
        "recommendation": "Ensure proper authentication and relay restrictions are configured. Consider using port 587 for submission."
    },
    53: {
        "service": "DNS",
        "severity": Severity.MEDIUM,
        "message": "DNS service exposed. May be vulnerable to DNS amplification attacks.",
        "recommendation": "Implement rate limiting, disable recursion for external queries, keep DNS software updated."
    },
    110: {
        "service": "POP3",
        "severity": Severity.HIGH,
        "message": "POP3 transmits credentials in plaintext",
        "recommendation": "Replace with POP3S (port 995) or use IMAP with TLS."
    },
    111: {
        "service": "RPC",
        "severity": Severity.HIGH,
        "message": "RPC portmapper exposed. Common target for attacks.",
        "recommendation": "Block from external access using firewall rules if not required."
    },
    135: {
        "service": "MSRPC",
        "severity": Severity.HIGH,
        "message": "Microsoft RPC endpoint exposed. Common target for Windows exploits.",
        "recommendation": "Block from external access. Ensure Windows is fully patched."
    },
    139: {
        "service": "NetBIOS",
        "severity": Severity.HIGH,
        "message": "NetBIOS session service exposed. Information disclosure risk.",
        "recommendation": "Block from external access. Disable NetBIOS over TCP/IP if not needed."
    },
    143: {
        "service": "IMAP",
        "severity": Severity.MEDIUM,
        "message": "IMAP without TLS may expose credentials",
        "recommendation": "Enforce IMAPS (port 993) or STARTTLS for all connections."
    },
    161: {
        "service": "SNMP",
        "severity": Severity.HIGH,
        "message": "SNMP exposed. May leak sensitive system information.",
        "recommendation": "Use SNMPv3 with authentication and encryption. Restrict community strings and access."
    },
    389: {
        "service": "LDAP",
        "severity": Severity.MEDIUM,
        "message": "LDAP without TLS may expose directory information and credentials.",
        "recommendation": "Implement LDAPS (port 636) or STARTTLS. Restrict anonymous binds."
    },
    443: {
        "service": "HTTPS",
        "severity": Severity.LOW,
        "message": "HTTPS is exposed. Verify TLS configuration.",
        "recommendation": "Ensure TLS 1.2+ only, disable weak ciphers, implement HSTS."
    },
    445: {
        "service": "SMB",
        "severity": Severity.CRITICAL,
        "message": "SMB port exposed. High-value target for ransomware and lateral movement.",
        "recommendation": "NEVER expose to internet. Block at perimeter firewall. Ensure SMBv1 is disabled."
    },
    512: {
        "service": "rexec",
        "severity": Severity.CRITICAL,
        "message": "Remote execution service. Extremely insecure.",
        "recommendation": "Disable immediately. Replace with SSH."
    },
    513: {
        "service": "rlogin",
        "severity": Severity.CRITICAL,
        "message": "Remote login service. No encryption, trust-based authentication.",
        "recommendation": "Disable immediately. Replace with SSH."
    },
    514: {
        "service": "rsh/syslog",
        "severity": Severity.HIGH,
        "message": "Remote shell or syslog. RSH is extremely insecure.",
        "recommendation": "Disable RSH. For syslog, use TLS-encrypted transport (port 6514)."
    },
    1433: {
        "service": "MSSQL",
        "severity": Severity.CRITICAL,
        "message": "Microsoft SQL Server exposed. Database attacks possible.",
        "recommendation": "NEVER expose to internet. Use VPN or firewall rules. Enable SQL Server audit logging."
    },
    1521: {
        "service": "Oracle DB",
        "severity": Severity.CRITICAL,
        "message": "Oracle Database listener exposed. Database attacks possible.",
        "recommendation": "NEVER expose to internet. Implement Oracle Database Vault and audit logging."
    },
    2049: {
        "service": "NFS",
        "severity": Severity.HIGH,
        "message": "NFS exposed. May allow unauthorized file access.",
        "recommendation": "Restrict exports to specific hosts. Use NFSv4 with Kerberos authentication."
    },
    3306: {
        "service": "MySQL",
        "severity": Severity.CRITICAL,
        "message": "MySQL database exposed. Database attacks possible.",
        "recommendation": "NEVER expose to internet. Bind to localhost or use firewall rules."
    },
    3389: {
        "service": "RDP",
        "severity": Severity.CRITICAL,
        "message": "Remote Desktop Protocol exposed. Primary target for brute-force and exploits.",
        "recommendation": "NEVER expose directly to internet. Use VPN or RD Gateway. Enable NLA."
    },
    5432: {
        "service": "PostgreSQL",
        "severity": Severity.CRITICAL,
        "message": "PostgreSQL database exposed. Database attacks possible.",
        "recommendation": "NEVER expose to internet. Use pg_hba.conf to restrict access."
    },
    5900: {
        "service": "VNC",
        "severity": Severity.HIGH,
        "message": "VNC remote access exposed. Often poorly secured.",
        "recommendation": "Use VPN for remote access. Ensure strong password and consider SSH tunneling."
    },
    6379: {
        "service": "Redis",
        "severity": Severity.CRITICAL,
        "message": "Redis exposed. Often has no authentication by default.",
        "recommendation": "NEVER expose to internet. Enable AUTH, bind to localhost, use firewall rules."
    },
    8080: {
        "service": "HTTP-Alt",
        "severity": Severity.MEDIUM,
        "message": "Alternative HTTP port. May expose admin interfaces.",
        "recommendation": "Identify the service. Ensure proper authentication and consider HTTPS."
    },
    27017: {
        "service": "MongoDB",
        "severity": Severity.CRITICAL,
        "message": "MongoDB exposed. Historically targeted for data theft.",
        "recommendation": "NEVER expose to internet. Enable authentication, bind to localhost."
    }
}


class VulnerabilityAnalyzer:
    """
    Vulnerability analyzer that identifies security issues from scan results.

    This class provides methods to:
    - Flag critical/risky open ports
    - Look up CVEs for detected service versions
    - Generate comprehensive vulnerability reports

    Features:
    - Filters out CVEs older than 2015 by default
    - Excludes obsolete systems (Windows XP, Solaris 2.x, etc.)
    - Requires specific version numbers for CVE lookups
    - Calculates relevance scores for better accuracy

    Attributes:
        api_timeout: Timeout in seconds for API requests.
        min_cve_year: Minimum year for CVE results.

    Example:
        >>> analyzer = VulnerabilityAnalyzer()
        >>> alerts = analyzer.analyze_ports(scan_result.hosts[0].ports)
        >>> for alert in alerts:
        ...     print(f"{alert.severity.value}: Port {alert.port} - {alert.message}")
    """

    # API endpoints
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CIRCL_API_BASE = "https://cve.circl.lu/api"

    def __init__(
        self,
        api_timeout: int = 10,
        min_cve_year: int = MIN_CVE_YEAR
    ) -> None:
        """
        Initialize the VulnerabilityAnalyzer.

        Args:
            api_timeout: Timeout in seconds for API requests (default: 10).
            min_cve_year: Minimum year for CVE results (default: 2015).
        """
        self.api_timeout = api_timeout
        self.min_cve_year = min_cve_year
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "CoreDefend-Scanner/1.0",
            "Accept": "application/json"
        })
        # Compile obsolete system patterns
        self._obsolete_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in OBSOLETE_SYSTEMS_PATTERNS
        ]

    def analyze_ports(self, ports: list) -> list[PortAlert]:
        """
        Analyze a list of ports for security issues.

        Args:
            ports: List of PortInfo objects from the scanner.

        Returns:
            List of PortAlert objects for identified issues.
        """
        alerts = []

        for port in ports:
            if port.state != "open":
                continue

            port_num = port.port

            # Check against critical ports dictionary
            if port_num in CRITICAL_PORTS:
                port_config = CRITICAL_PORTS[port_num]
                alerts.append(PortAlert(
                    port=port_num,
                    service=port.service or port_config["service"],
                    severity=port_config["severity"],
                    message=port_config["message"],
                    recommendation=port_config["recommendation"]
                ))
            elif port.state == "open":
                # Generate info alert for any open port not in critical list
                alerts.append(PortAlert(
                    port=port_num,
                    service=port.service,
                    severity=Severity.INFO,
                    message=f"Port {port_num} ({port.service}) is open",
                    recommendation="Verify this service is required and properly configured."
                ))

        # Sort by severity (CRITICAL first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
            Severity.UNKNOWN: 5
        }
        alerts.sort(key=lambda x: severity_order.get(x.severity, 5))

        return alerts

    def _is_generic_service(self, service_name: str) -> bool:
        """
        Check if a service name is too generic for CVE searches.

        Args:
            service_name: The service name to check.

        Returns:
            True if the service is generic and should be skipped.
        """
        if not service_name:
            return True
        return service_name.lower().strip() in GENERIC_SERVICES_BLACKLIST

    def _has_valid_version(self, version_string: str) -> bool:
        """
        Check if a version string contains a valid version number.

        Args:
            version_string: The version string to check (e.g., "Apache 2.4.49").

        Returns:
            True if a valid version pattern is found.
        """
        if not version_string:
            return False
        return VERSION_PATTERN.search(version_string) is not None

    def _extract_version_info(self, port) -> Optional[str]:
        """
        Extract version information from port data for CVE lookup.

        Only returns a search string if:
        - Product name is not a generic service name
        - A specific version number is detected

        Args:
            port: PortInfo object containing service information.

        Returns:
            Formatted string for CVE search or None if no valid version.
        """
        product = port.product
        version = port.version
        service = port.service

        # Build the search string
        if product and version:
            search_string = f"{product} {version}"
        elif product:
            # Product without version - only search if product is specific enough
            if self._is_generic_service(product):
                return None
            search_string = product
        elif service and version:
            search_string = f"{service} {version}"
        else:
            # No useful version information
            return None

        # Validate we have a real version number
        if not self._has_valid_version(search_string):
            # Allow product-only searches for specific products
            if not product or self._is_generic_service(product):
                return None

        return search_string

    def _is_obsolete_system(self, description: str) -> bool:
        """
        Check if a CVE description refers to an obsolete system.

        Args:
            description: The CVE description text.

        Returns:
            True if the CVE is for an obsolete system.
        """
        if not description:
            return False

        description_lower = description.lower()

        for pattern in self._obsolete_patterns:
            if pattern.search(description_lower):
                return True

        return False

    def _parse_cve_year(self, published_date: str) -> Optional[int]:
        """
        Extract the year from a CVE published date.

        Args:
            published_date: Date string (e.g., "2021-04-15" or "2021-04-15T12:00:00").

        Returns:
            Year as integer or None if parsing fails.
        """
        try:
            if not published_date or published_date == "Unknown":
                return None
            # Extract just the year
            year_match = re.match(r'(\d{4})', published_date)
            if year_match:
                return int(year_match.group(1))
        except (ValueError, TypeError):
            pass
        return None

    def _calculate_relevance(
        self,
        cve_description: str,
        search_term: str,
        published_year: Optional[int]
    ) -> float:
        """
        Calculate a relevance score for a CVE based on how well it matches.

        Args:
            cve_description: The CVE description.
            search_term: The original search term (e.g., "Apache 2.4.49").
            published_year: The year the CVE was published.

        Returns:
            Relevance score between 0.0 and 1.0.
        """
        score = 0.0

        if not cve_description or not search_term:
            return score

        description_lower = cve_description.lower()
        search_parts = search_term.lower().split()

        # Check for product name match
        if len(search_parts) >= 1:
            product = search_parts[0]
            if product in description_lower:
                score += 0.4

        # Check for version match
        if len(search_parts) >= 2:
            version = search_parts[1]
            if version in description_lower:
                score += 0.4

        # Bonus for recent CVEs (within last 5 years)
        if published_year:
            current_year = datetime.now().year
            years_old = current_year - published_year
            if years_old <= 2:
                score += 0.2
            elif years_old <= 5:
                score += 0.1

        return min(score, 1.0)

    def _parse_cvss_score(self, cve_data: dict) -> tuple[Optional[float], Severity]:
        """
        Parse CVSS score and determine severity from CVE data.

        Args:
            cve_data: CVE data dictionary from API response.

        Returns:
            Tuple of (cvss_score, severity).
        """
        metrics = cve_data.get("metrics", {})

        # Try CVSS 3.1 first, then 3.0, then 2.0
        for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if cvss_version in metrics and metrics[cvss_version]:
                cvss_data = metrics[cvss_version][0]
                if "cvssData" in cvss_data:
                    score = cvss_data["cvssData"].get("baseScore")
                    if score is not None:
                        # Determine severity from score
                        if score >= 9.0:
                            severity = Severity.CRITICAL
                        elif score >= 7.0:
                            severity = Severity.HIGH
                        elif score >= 4.0:
                            severity = Severity.MEDIUM
                        elif score > 0:
                            severity = Severity.LOW
                        else:
                            severity = Severity.INFO
                        return float(score), severity

        return None, Severity.UNKNOWN

    def _filter_cve(
        self,
        cve_id: str,
        description: str,
        published_date: str,
        search_term: str
    ) -> tuple[bool, float]:
        """
        Determine if a CVE should be included in results.

        Args:
            cve_id: The CVE identifier.
            description: The CVE description.
            published_date: The publication date.
            search_term: The original search term.

        Returns:
            Tuple of (should_include, relevance_score).
        """
        # Parse the year
        published_year = self._parse_cve_year(published_date)

        # Filter by year
        if published_year and published_year < self.min_cve_year:
            return False, 0.0

        # Filter obsolete systems
        if self._is_obsolete_system(description):
            return False, 0.0

        # Calculate relevance
        relevance = self._calculate_relevance(description, search_term, published_year)

        # Require minimum relevance score
        if relevance < 0.3:
            return False, relevance

        return True, relevance

    def search_cves_nvd(
        self,
        keyword: str,
        max_results: int = 5
    ) -> list[CVEInfo]:
        """
        Search for CVEs using the NIST NVD API with filtering.

        Args:
            keyword: Search keyword (e.g., "Apache 2.4.49").
            max_results: Maximum number of results to return.

        Returns:
            List of CVEInfo objects matching the search.
        """
        cves = []

        try:
            # Request more results to account for filtering
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results * 3
            }

            response = self._session.get(
                self.NVD_API_BASE,
                params=params,
                timeout=self.api_timeout
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                if len(cves) >= max_results:
                    break

                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "Unknown")

                # Get description
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Get published date
                published = cve_data.get("published", "Unknown")
                if published != "Unknown":
                    published = published[:10]  # Extract date only

                # Apply filters
                should_include, relevance = self._filter_cve(
                    cve_id, description, published, keyword
                )

                if not should_include:
                    continue

                # Get CVSS score and severity
                cvss_score, severity = self._parse_cvss_score(cve_data)

                # Get references
                references = []
                for ref in cve_data.get("references", [])[:3]:
                    references.append(ref.get("url", ""))

                cves.append(CVEInfo(
                    cve_id=cve_id,
                    description=description[:500] + "..." if len(description) > 500 else description,
                    severity=severity,
                    cvss_score=cvss_score,
                    published_date=published,
                    references=references,
                    relevance_score=relevance
                ))

        except requests.exceptions.Timeout:
            pass  # Silently handle timeout
        except requests.exceptions.RequestException:
            pass  # Silently handle network errors
        except (KeyError, ValueError):
            pass  # Silently handle parsing errors

        # Sort by relevance score (highest first)
        cves.sort(key=lambda x: x.relevance_score, reverse=True)

        return cves[:max_results]

    def search_cves_circl(
        self,
        keyword: str,
        max_results: int = 5
    ) -> list[CVEInfo]:
        """
        Search for CVEs using the CIRCL CVE API (fallback) with filtering.

        Args:
            keyword: Search keyword (e.g., "Apache 2.4.49").
            max_results: Maximum number of results to return.

        Returns:
            List of CVEInfo objects matching the search.
        """
        cves = []

        try:
            # CIRCL API uses a different endpoint structure
            # Extract product name for search
            parts = keyword.split()
            if not parts:
                return cves

            # Use first part as vendor/product
            search_term = parts[0].lower()
            if self._is_generic_service(search_term):
                return cves

            url = f"{self.CIRCL_API_BASE}/search/{search_term}"

            response = self._session.get(url, timeout=self.api_timeout)
            response.raise_for_status()

            data = response.json()

            if isinstance(data, list):
                for cve_data in data:
                    if len(cves) >= max_results:
                        break

                    cve_id = cve_data.get("id", "Unknown")
                    description = cve_data.get("summary", "No description available")
                    published = cve_data.get("Published", "Unknown")
                    if published and published != "Unknown":
                        published = published[:10]

                    # Apply filters
                    should_include, relevance = self._filter_cve(
                        cve_id, description, published, keyword
                    )

                    if not should_include:
                        continue

                    # Determine severity from CVSS
                    cvss = cve_data.get("cvss")
                    if cvss is not None:
                        try:
                            cvss = float(cvss)
                            if cvss >= 9.0:
                                severity = Severity.CRITICAL
                            elif cvss >= 7.0:
                                severity = Severity.HIGH
                            elif cvss >= 4.0:
                                severity = Severity.MEDIUM
                            else:
                                severity = Severity.LOW
                        except (ValueError, TypeError):
                            cvss = None
                            severity = Severity.UNKNOWN
                    else:
                        severity = Severity.UNKNOWN

                    cves.append(CVEInfo(
                        cve_id=cve_id,
                        description=description[:500],
                        severity=severity,
                        cvss_score=cvss,
                        published_date=published,
                        references=cve_data.get("references", [])[:3],
                        relevance_score=relevance
                    ))

        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass
        except (KeyError, ValueError, TypeError):
            pass

        # Sort by relevance score
        cves.sort(key=lambda x: x.relevance_score, reverse=True)

        return cves[:max_results]

    def search_cves(
        self,
        service_version: str,
        max_results: int = 5
    ) -> list[CVEInfo]:
        """
        Search for CVEs using multiple APIs with fallback.

        Tries NVD first, then falls back to CIRCL if needed.

        Args:
            service_version: Service and version string (e.g., "Apache 2.4.49").
            max_results: Maximum number of results to return.

        Returns:
            List of CVEInfo objects matching the search.
        """
        # Clean up the search term
        cleaned = re.sub(r'[^\w\s\.\-]', '', service_version)

        # Try NVD first
        cves = self.search_cves_nvd(cleaned, max_results)

        # If NVD returned fewer than requested, try CIRCL for more
        if len(cves) < max_results:
            remaining = max_results - len(cves)
            circl_cves = self.search_cves_circl(cleaned, remaining)
            # Avoid duplicates
            existing_ids = {c.cve_id for c in cves}
            for cve in circl_cves:
                if cve.cve_id not in existing_ids:
                    cves.append(cve)

        return cves[:max_results]

    def analyze_services(self, ports: list) -> dict[str, list[CVEInfo]]:
        """
        Analyze services for known CVEs based on version information.

        Only searches for CVEs when:
        - A specific product name is identified (not generic like "http")
        - A version number is detected

        Args:
            ports: List of PortInfo objects from the scanner.

        Returns:
            Dictionary mapping service identifiers to lists of CVEInfo objects.
        """
        service_cves = {}

        for port in ports:
            if port.state != "open":
                continue

            version_info = self._extract_version_info(port)
            if not version_info:
                continue

            # Skip if we've already searched for this service/version
            if version_info in service_cves:
                continue

            cves = self.search_cves(version_info)
            if cves:
                service_cves[version_info] = cves

        return service_cves

    def generate_report(self, ports: list) -> VulnerabilityReport:
        """
        Generate a comprehensive vulnerability report for scanned ports.

        Args:
            ports: List of PortInfo objects from the scanner.

        Returns:
            VulnerabilityReport containing all findings.
        """
        report = VulnerabilityReport()

        # Analyze ports for critical issues
        report.port_alerts = self.analyze_ports(ports)

        # Search for CVEs based on service versions
        report.service_cve_map = self.analyze_services(ports)

        # Flatten CVE findings
        for service, cves in report.service_cve_map.items():
            report.cve_findings.extend(cves)

        return report

    @staticmethod
    def get_critical_ports() -> dict:
        """
        Get the dictionary of critical ports and their security information.

        Returns:
            Dictionary of critical ports configuration.
        """
        return CRITICAL_PORTS.copy()

    @staticmethod
    def count_by_severity(alerts: list[PortAlert]) -> dict[Severity, int]:
        """
        Count alerts by severity level.

        Args:
            alerts: List of PortAlert objects.

        Returns:
            Dictionary mapping Severity to count.
        """
        counts = {severity: 0 for severity in Severity}
        for alert in alerts:
            counts[alert.severity] += 1
        return counts
