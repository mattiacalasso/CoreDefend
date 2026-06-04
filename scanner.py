"""
CoreDefend - Network Scanner Module

This module provides network scanning capabilities using Nmap.
It handles port scanning, service detection, and OS fingerprinting.

Author: CoreDefend Security Team
License: MIT
"""

import nmap
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class PortInfo:
    """Data class representing information about a scanned port."""
    port: int
    state: str
    protocol: str
    service: str
    version: str
    product: str
    extra_info: str


@dataclass
class HostInfo:
    """Data class representing information about a scanned host."""
    ip: str
    hostname: str
    state: str
    os_match: str
    os_accuracy: int
    ports: list[PortInfo] = field(default_factory=list)


@dataclass
class ScanResult:
    """Data class representing the complete scan result."""
    target: str
    scan_type: str
    command_line: str
    hosts: list[HostInfo] = field(default_factory=list)
    error: Optional[str] = None
    scan_stats: dict = field(default_factory=dict)


class NmapScannerError(Exception):
    """Custom exception for Nmap scanner errors."""
    pass


class NmapNotInstalledError(NmapScannerError):
    """Exception raised when Nmap is not installed on the system."""
    pass


class InsufficientPermissionsError(NmapScannerError):
    """Exception raised when root/admin permissions are required."""
    pass


class HostUnreachableError(NmapScannerError):
    """Exception raised when the target host is unreachable."""
    pass


class NetworkScanner:
    """
    Network scanner class that wraps python-nmap functionality.

    Provides methods for different types of network scans including
    fast scans and aggressive scans with OS/version detection.

    Attributes:
        scanner: The underlying nmap.PortScanner instance.

    Example:
        >>> scanner = NetworkScanner()
        >>> result = scanner.fast_scan("192.168.1.1")
        >>> for host in result.hosts:
        ...     print(f"Host: {host.ip}, Open ports: {len(host.ports)}")
    """

    # Scan type configurations
    SCAN_TYPES = {
        "fast": {
            "arguments": "-T4 -F",
            "description": "Fast scan of most common ports"
        },
        "aggressive": {
            "arguments": "-T4 -A -v",
            "description": "Aggressive scan with OS and version detection"
        },
        "stealth": {
            "arguments": "-sS -T2",
            "description": "Stealth SYN scan (requires root)"
        },
        "udp": {
            "arguments": "-sU -T4 --top-ports 100",
            "description": "UDP scan of top 100 ports (requires root)"
        }
    }

    def __init__(self) -> None:
        """
        Initialize the NetworkScanner.

        Raises:
            NmapNotInstalledError: If Nmap is not installed on the system.
        """
        try:
            self.scanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            raise NmapNotInstalledError(
                "Nmap is not installed or not found in PATH. "
                "Please install Nmap: https://nmap.org/download.html"
            ) from e

    def _validate_target(self, target: str) -> str:
        """
        Validate and sanitize the scan target.

        Args:
            target: IP address, hostname, or CIDR range to scan.

        Returns:
            Sanitized target string.

        Raises:
            ValueError: If the target is empty or contains invalid characters.
        """
        if not target or not target.strip():
            raise ValueError("Target cannot be empty")

        # Basic sanitization - remove potentially dangerous characters
        sanitized = target.strip()
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>']

        for char in dangerous_chars:
            if char in sanitized:
                raise ValueError(f"Invalid character in target: {char}")

        return sanitized

    def _parse_scan_results(self, target: str, scan_type: str) -> ScanResult:
        """
        Parse raw Nmap scan results into structured data.

        Args:
            target: The original scan target.
            scan_type: The type of scan performed.

        Returns:
            ScanResult object containing parsed scan data.
        """
        result = ScanResult(
            target=target,
            scan_type=scan_type,
            command_line=self.scanner.command_line(),
            scan_stats=self.scanner.scanstats()
        )

        for host_ip in self.scanner.all_hosts():
            host_data = self.scanner[host_ip]

            # Extract hostname
            hostnames = host_data.hostnames()
            hostname = hostnames[0]['name'] if hostnames else ""

            # Extract OS information
            os_match = ""
            os_accuracy = 0
            if 'osmatch' in host_data and host_data['osmatch']:
                best_match = host_data['osmatch'][0]
                os_match = best_match.get('name', '')
                os_accuracy = int(best_match.get('accuracy', 0))

            host_info = HostInfo(
                ip=host_ip,
                hostname=hostname,
                state=host_data.state(),
                os_match=os_match,
                os_accuracy=os_accuracy
            )

            # Extract port information
            for protocol in ['tcp', 'udp']:
                if protocol in host_data:
                    for port, port_data in host_data[protocol].items():
                        port_info = PortInfo(
                            port=port,
                            state=port_data.get('state', 'unknown'),
                            protocol=protocol,
                            service=port_data.get('name', 'unknown'),
                            version=port_data.get('version', ''),
                            product=port_data.get('product', ''),
                            extra_info=port_data.get('extrainfo', '')
                        )
                        host_info.ports.append(port_info)

            result.hosts.append(host_info)

        return result

    def scan(
        self,
        target: str,
        scan_type: str = "fast",
        custom_arguments: Optional[str] = None
    ) -> ScanResult:
        """
        Perform a network scan on the specified target.

        Args:
            target: IP address, hostname, or CIDR range to scan.
            scan_type: Type of scan to perform ('fast', 'aggressive', 'stealth', 'udp').
            custom_arguments: Optional custom Nmap arguments (overrides scan_type).

        Returns:
            ScanResult object containing scan results.

        Raises:
            NmapScannerError: If an error occurs during scanning.
            ValueError: If the target or scan type is invalid.

        Example:
            >>> scanner = NetworkScanner()
            >>> result = scanner.scan("192.168.1.1", scan_type="aggressive")
            >>> print(f"Found {len(result.hosts)} hosts")
        """
        # Validate target
        target = self._validate_target(target)

        # Get scan arguments
        if custom_arguments:
            arguments = custom_arguments
        elif scan_type in self.SCAN_TYPES:
            arguments = self.SCAN_TYPES[scan_type]["arguments"]
        else:
            raise ValueError(
                f"Invalid scan type: {scan_type}. "
                f"Valid types: {list(self.SCAN_TYPES.keys())}"
            )

        try:
            self.scanner.scan(hosts=target, arguments=arguments)
        except nmap.PortScannerError as e:
            error_msg = str(e).lower()

            if "permission" in error_msg or "root" in error_msg or "requires root" in error_msg:
                raise InsufficientPermissionsError(
                    "This scan type requires root/administrator privileges. "
                    "Please run the application with elevated permissions."
                ) from e
            elif "host seems down" in error_msg or "0 hosts up" in error_msg:
                raise HostUnreachableError(
                    f"Target host {target} appears to be down or unreachable. "
                    "Verify the target is online and accessible."
                ) from e
            else:
                raise NmapScannerError(f"Scan error: {e}") from e

        # Check if any hosts were found
        result = self._parse_scan_results(target, scan_type)

        if not result.hosts:
            result.error = (
                f"No hosts found for target {target}. "
                "The host may be down or blocking probe packets."
            )

        return result

    def fast_scan(self, target: str) -> ScanResult:
        """
        Perform a fast scan of the most common ports.

        Args:
            target: IP address, hostname, or CIDR range to scan.

        Returns:
            ScanResult object containing scan results.
        """
        return self.scan(target, scan_type="fast")

    def aggressive_scan(self, target: str) -> ScanResult:
        """
        Perform an aggressive scan with OS and version detection.

        Note: This scan type may require root/administrator privileges
        for certain features like OS detection.

        Args:
            target: IP address, hostname, or CIDR range to scan.

        Returns:
            ScanResult object containing scan results.
        """
        return self.scan(target, scan_type="aggressive")

    @staticmethod
    def get_scan_types() -> dict:
        """
        Get available scan types and their descriptions.

        Returns:
            Dictionary mapping scan type names to their configurations.
        """
        return NetworkScanner.SCAN_TYPES.copy()

    @staticmethod
    def check_nmap_installed() -> tuple[bool, str]:
        """
        Check if Nmap is installed and return version information.

        Returns:
            Tuple of (is_installed: bool, version_or_error: str)
        """
        try:
            scanner = nmap.PortScanner()
            version = scanner.nmap_version()
            return True, f"Nmap {version[0]}.{version[1]}"
        except nmap.PortScannerError as e:
            return False, str(e)
