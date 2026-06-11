"""
CoreDefend - Network Scanner Module

This module provides network scanning capabilities using Nmap.
It handles port scanning, service detection, and OS fingerprinting.

Author: Mattia Calasso
License: MIT
"""

import nmap
import subprocess
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Optional, Generator, Callable
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

    def scan_with_progress(
        self,
        target: str,
        scan_type: str = "fast",
        custom_arguments: Optional[str] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None
    ) -> ScanResult:
        """
        Perform a network scan with real-time progress updates.

        Args:
            target: IP address, hostname, or CIDR range to scan.
            scan_type: Type of scan to perform (used if custom_arguments is None).
            custom_arguments: Custom nmap arguments string (overrides scan_type).
            progress_callback: Callback function(percent, status_message).

        Returns:
            ScanResult object containing scan results.
        """
        target = self._validate_target(target)

        # Find nmap executable
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            raise NmapNotInstalledError("Nmap is not installed or not found in PATH.")

        # Get scan arguments
        if custom_arguments:
            arguments = custom_arguments
        elif scan_type in self.SCAN_TYPES:
            arguments = self.SCAN_TYPES[scan_type]["arguments"]
        else:
            arguments = "-T4 -F"  # Default fallback

        # Build command with progress stats and XML output
        cmd = [
            nmap_path,
            "--stats-every", "2s",
            "-oX", "-",  # XML output to stdout
            *arguments.split(),
            target
        ]

        # Progress patterns
        progress_pattern = re.compile(r'About (\d+\.?\d*)% done')
        task_pattern = re.compile(r'(\w+(?:\s+\w+)*)\s+Timing:')

        current_progress = 0
        current_task = "Initializing scan..."

        try:
            # Use threads to read stdout and stderr simultaneously
            import threading
            import queue

            xml_queue = queue.Queue()
            stderr_queue = queue.Queue()

            def read_stdout(pipe, q):
                try:
                    for line in pipe:
                        q.put(line)
                finally:
                    q.put(None)  # Signal end

            def read_stderr(pipe, q):
                try:
                    for line in pipe:
                        q.put(line)
                finally:
                    q.put(None)  # Signal end

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Start reader threads
            stdout_thread = threading.Thread(target=read_stdout, args=(process.stdout, xml_queue))
            stderr_thread = threading.Thread(target=read_stderr, args=(process.stderr, stderr_queue))
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            xml_output = []
            stdout_done = False
            stderr_done = False

            while not (stdout_done and stderr_done):
                # Read from stderr for progress
                try:
                    while True:
                        line = stderr_queue.get_nowait()
                        if line is None:
                            stderr_done = True
                            break

                        progress_match = progress_pattern.search(line)
                        if progress_match:
                            current_progress = int(float(progress_match.group(1)))

                        task_match = task_pattern.search(line)
                        if task_match:
                            current_task = task_match.group(1)

                        if progress_callback:
                            progress_callback(current_progress, current_task)

                except queue.Empty:
                    pass

                # Read from stdout for XML
                try:
                    while True:
                        line = xml_queue.get_nowait()
                        if line is None:
                            stdout_done = True
                            break
                        xml_output.append(line)
                except queue.Empty:
                    pass

                # Small sleep to prevent busy waiting
                if not (stdout_done and stderr_done):
                    import time
                    time.sleep(0.1)

            # Wait for process to complete
            process.wait()
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

            if progress_callback:
                progress_callback(100, "Scan complete")

            # Parse XML output
            xml_string = ''.join(xml_output)
            scan_label = "custom" if custom_arguments else scan_type
            return self._parse_xml_results(xml_string, target, scan_label, arguments)

        except subprocess.SubprocessError as e:
            raise NmapScannerError(f"Failed to execute nmap: {e}") from e
        except Exception as e:
            raise NmapScannerError(f"Scan failed: {e}") from e

    def _parse_xml_results(
        self,
        xml_string: str,
        target: str,
        scan_type: str,
        arguments: str = ""
    ) -> ScanResult:
        """Parse nmap XML output into ScanResult."""
        result = ScanResult(
            target=target,
            scan_type=scan_type,
            command_line=f"nmap {arguments} {target}"
        )

        try:
            root = ET.fromstring(xml_string)
        except ET.ParseError as e:
            result.error = f"Failed to parse scan results: {e}"
            return result

        # Parse hosts
        for host_elem in root.findall('.//host'):
            status = host_elem.find('status')
            if status is None or status.get('state') != 'up':
                continue

            # Get IP address
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                addr_elem = host_elem.find("address[@addrtype='ipv6']")
            ip = addr_elem.get('addr') if addr_elem is not None else "unknown"

            # Get hostname
            hostname = ""
            hostname_elem = host_elem.find('.//hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', '')

            # Get OS info
            os_match = ""
            os_accuracy = 0
            osmatch_elem = host_elem.find('.//osmatch')
            if osmatch_elem is not None:
                os_match = osmatch_elem.get('name', '')
                os_accuracy = int(osmatch_elem.get('accuracy', 0))

            host_info = HostInfo(
                ip=ip,
                hostname=hostname,
                state='up',
                os_match=os_match,
                os_accuracy=os_accuracy
            )

            # Parse ports
            for port_elem in host_elem.findall('.//port'):
                state_elem = port_elem.find('state')
                service_elem = port_elem.find('service')

                port_info = PortInfo(
                    port=int(port_elem.get('portid', 0)),
                    state=state_elem.get('state', 'unknown') if state_elem is not None else 'unknown',
                    protocol=port_elem.get('protocol', 'tcp'),
                    service=service_elem.get('name', 'unknown') if service_elem is not None else 'unknown',
                    version=service_elem.get('version', '') if service_elem is not None else '',
                    product=service_elem.get('product', '') if service_elem is not None else '',
                    extra_info=service_elem.get('extrainfo', '') if service_elem is not None else ''
                )
                host_info.ports.append(port_info)

            result.hosts.append(host_info)

        if not result.hosts:
            result.error = f"No hosts found for target {target}."

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
