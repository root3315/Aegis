"""
Network and vulnerability scanning modules for Aegis.

Provides port scanning, service detection, and vulnerability assessment.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import time

from .config import ScanConfig, SecurityLevel
from .utils import get_logger, validate_ip_address, resolve_hostname, ProgressBar


class PortState(Enum):
    """Port status enumeration."""
    OPEN = auto()
    CLOSED = auto()
    FILTERED = auto()
    UNKNOWN = auto()


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PortResult:
    """Result of a port scan."""
    port: int
    state: PortState
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""
    response_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "port": self.port,
            "state": self.state.name,
            "protocol": self.protocol,
            "service": self.service,
            "banner": self.banner,
            "response_time_ms": round(self.response_time * 1000, 2),
        }


@dataclass
class Vulnerability:
    """Detected vulnerability information."""
    id: str
    name: str
    severity: VulnerabilitySeverity
    description: str
    affected_port: int
    affected_service: str
    remediation: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "affected_port": self.affected_port,
            "affected_service": self.affected_service,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
        }


@dataclass
class ScanResult:
    """Complete scan result container."""
    target: str
    target_ip: str
    scan_start: str
    scan_end: str
    duration: float
    ports_scanned: int
    open_ports: List[PortResult] = field(default_factory=list)
    closed_ports: List[PortResult] = field(default_factory=list)
    filtered_ports: List[PortResult] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "target_ip": self.target_ip,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "duration_seconds": round(self.duration, 2),
            "ports_scanned": self.ports_scanned,
            "summary": {
                "open": len(self.open_ports),
                "closed": len(self.closed_ports),
                "filtered": len(self.filtered_ports),
                "vulnerabilities": len(self.vulnerabilities),
            },
            "open_ports": [p.to_dict() for p in self.open_ports],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "services": self.services,
        }


class NetworkScanner:
    """
    Network port scanner with service detection.
    
    Performs TCP connect scans with configurable timing and threading.
    """
    
    # Common service signatures for basic service detection
    SERVICE_SIGNATURES: Dict[int, str] = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MS-RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }
    
    def __init__(self, config: ScanConfig) -> None:
        """
        Initialize network scanner.
        
        Args:
            config: Scan configuration parameters
        """
        self.config = config
        self.logger = get_logger("aegis.scanner")
        self._stop_flag = threading.Event()
    
    def scan_port(self, port: int) -> PortResult:
        """
        Scan a single port.
        
        Args:
            port: Port number to scan
            
        Returns:
            PortResult with scan information
        """
        start_time = time.time()
        state = PortState.UNKNOWN
        banner = ""
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            
            result = sock.connect_ex((self.config.target, port))
            response_time = time.time() - start_time
            
            if result == 0:
                state = PortState.OPEN
                
                # Attempt banner grabbing for service detection
                if self.config.security_level != SecurityLevel.STEALTH:
                    try:
                        sock.settimeout(1.0)
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    except socket.timeout:
                        pass
                    except Exception:
                        pass
                
                # Identify service
                service = self.SERVICE_SIGNATURES.get(port, "unknown")
                if banner and not service:
                    service = self._identify_service_from_banner(banner)
                
            elif result == 113:  # Connection refused with ICMP unreachable
                state = PortState.FILTERED
            else:
                state = PortState.CLOSED
            
            sock.close()
            
        except socket.timeout:
            state = PortState.FILTERED
            response_time = self.config.timeout
        except socket.error as e:
            self.logger.debug(f"Socket error on port {port}: {e}")
            state = PortState.FILTERED
            response_time = time.time() - start_time
        
        return PortResult(
            port=port,
            state=state,
            protocol="tcp",
            service=self.SERVICE_SIGNATURES.get(port, ""),
            banner=banner[:200] if banner else "",
            response_time=response_time,
        )
    
    def _identify_service_from_banner(self, banner: str) -> str:
        """
        Identify service from banner string.
        
        Args:
            banner: Service banner string
            
        Returns:
            Identified service name
        """
        banner_lower = banner.lower()
        
        if "ssh" in banner_lower:
            return "SSH"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "http" in banner_lower:
            return "HTTP"
        elif "smtp" in banner_lower:
            return "SMTP"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "postgres" in banner_lower:
            return "PostgreSQL"
        elif "redis" in banner_lower:
            return "Redis"
        elif "mongodb" in banner_lower:
            return "MongoDB"
        elif "nginx" in banner_lower or "apache" in banner_lower:
            return "HTTP"
        
        return "unknown"
    
    def scan(self, progress_callback: Optional[callable] = None) -> List[PortResult]:
        """
        Perform port scan on all configured ports.
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of PortResult for all scanned ports
        """
        ports = self.config.get_ports()
        results: List[PortResult] = []
        
        self.logger.info(f"Starting port scan on {self.config.target}")
        self.logger.info(f"Scanning {len(ports)} ports with {self.config.threads} threads")
        
        if self.config.verbose:
            progress = ProgressBar(len(ports), "Scanning")
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in ports
            }
            
            completed = 0
            for future in as_completed(future_to_port):
                if self._stop_flag.is_set():
                    break
                
                port = future_to_port[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {e}")
                    results.append(PortResult(
                        port=port,
                        state=PortState.UNKNOWN,
                        protocol="tcp",
                    ))
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(ports))
                if self.config.verbose:
                    progress.update(completed)
        
        # Sort results by port number
        results.sort(key=lambda x: x.port)
        
        self.logger.info(f"Scan complete. Found {sum(1 for r in results if r.state == PortState.OPEN)} open ports")
        
        return results
    
    def stop(self) -> None:
        """Stop the scanning process."""
        self._stop_flag.set()
        self.logger.info("Scan stop requested")


class VulnerabilityScanner:
    """
    Vulnerability assessment scanner.
    
    Checks for common vulnerabilities based on detected services.
    """
    
    # Basic vulnerability database for common services
    VULNERABILITY_DB: Dict[str, List[Dict[str, Any]]] = {
        "FTP": [
            {
                "id": "FTP-001",
                "name": "Anonymous FTP Access",
                "severity": VulnerabilitySeverity.MEDIUM,
                "description": "FTP server allows anonymous login which may expose sensitive files.",
                "remediation": "Disable anonymous FTP access if not required.",
                "cve_id": "",
                "cvss_score": 5.3,
            },
            {
                "id": "FTP-002",
                "name": "Unencrypted FTP",
                "severity": VulnerabilitySeverity.HIGH,
                "description": "FTP transmits credentials and data in plaintext.",
                "remediation": "Use SFTP or FTPS instead of plain FTP.",
                "cve_id": "",
                "cvss_score": 7.5,
            },
        ],
        "Telnet": [
            {
                "id": "TELNET-001",
                "name": "Unencrypted Remote Access",
                "severity": VulnerabilitySeverity.CRITICAL,
                "description": "Telnet transmits all data including credentials in plaintext.",
                "remediation": "Replace Telnet with SSH for secure remote access.",
                "cve_id": "",
                "cvss_score": 9.8,
            },
        ],
        "SMB": [
            {
                "id": "SMB-001",
                "name": "SMBv1 Enabled",
                "severity": VulnerabilitySeverity.HIGH,
                "description": "SMBv1 is deprecated and vulnerable to multiple exploits.",
                "remediation": "Disable SMBv1 and use SMBv2 or SMBv3.",
                "cve_id": "CVE-2017-0144",
                "cvss_score": 8.1,
            },
        ],
        "HTTP": [
            {
                "id": "HTTP-001",
                "name": "Unencrypted HTTP",
                "severity": VulnerabilitySeverity.MEDIUM,
                "description": "HTTP traffic is unencrypted and can be intercepted.",
                "remediation": "Implement HTTPS with valid TLS certificates.",
                "cve_id": "",
                "cvss_score": 5.9,
            },
        ],
        "Redis": [
            {
                "id": "REDIS-001",
                "name": "Unauthenticated Redis",
                "severity": VulnerabilitySeverity.CRITICAL,
                "description": "Redis server accessible without authentication.",
                "remediation": "Enable Redis authentication and bind to localhost.",
                "cve_id": "",
                "cvss_score": 9.8,
            },
        ],
        "MongoDB": [
            {
                "id": "MONGO-001",
                "name": "Unauthenticated MongoDB",
                "severity": VulnerabilitySeverity.CRITICAL,
                "description": "MongoDB server accessible without authentication.",
                "remediation": "Enable MongoDB authentication and configure access control.",
                "cve_id": "",
                "cvss_score": 9.8,
            },
        ],
        "MySQL": [
            {
                "id": "MYSQL-001",
                "name": "Remote MySQL Access",
                "severity": VulnerabilitySeverity.MEDIUM,
                "description": "MySQL server accepts remote connections which may be insecure.",
                "remediation": "Restrict MySQL to localhost or use SSL connections.",
                "cve_id": "",
                "cvss_score": 5.3,
            },
        ],
        "RDP": [
            {
                "id": "RDP-001",
                "name": "RDP Network Level Authentication",
                "severity": VulnerabilitySeverity.MEDIUM,
                "description": "RDP may be vulnerable if NLA is not enforced.",
                "remediation": "Enable Network Level Authentication for RDP.",
                "cve_id": "CVE-2019-0708",
                "cvss_score": 7.5,
            },
        ],
    }
    
    def __init__(self, config: ScanConfig) -> None:
        """
        Initialize vulnerability scanner.
        
        Args:
            config: Scan configuration parameters
        """
        self.config = config
        self.logger = get_logger("aegis.vuln_scanner")
    
    def check_vulnerabilities(self, port_results: List[PortResult]) -> List[Vulnerability]:
        """
        Check for vulnerabilities based on detected services.
        
        Args:
            port_results: List of port scan results
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities: List[Vulnerability] = []
        
        self.logger.info("Starting vulnerability assessment")
        
        for result in port_results:
            if result.state != PortState.OPEN:
                continue
            
            service = result.service or "unknown"
            
            # Check vulnerability database for this service
            if service in self.VULNERABILITY_DB:
                for vuln_data in self.VULNERABILITY_DB[service]:
                    # Additional checks for specific vulnerabilities
                    if self._check_vulnerability(vuln_data, result):
                        vuln = Vulnerability(
                            id=vuln_data["id"],
                            name=vuln_data["name"],
                            severity=vuln_data["severity"],
                            description=vuln_data["description"],
                            affected_port=result.port,
                            affected_service=service,
                            remediation=vuln_data["remediation"],
                            cve_id=vuln_data.get("cve_id", ""),
                            cvss_score=vuln_data.get("cvss_score", 0.0),
                        )
                        vulnerabilities.append(vuln)
                        self.logger.warning(f"Vulnerability detected: {vuln.name} on port {result.port}")
            
            # Check for default/weak configurations
            custom_vulns = self._check_custom_vulnerabilities(result)
            vulnerabilities.extend(custom_vulns)
        
        # Sort by severity
        severity_order = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 1,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 3,
            VulnerabilitySeverity.INFO: 4,
        }
        vulnerabilities.sort(key=lambda v: severity_order[v.severity])
        
        self.logger.info(f"Vulnerability assessment complete. Found {len(vulnerabilities)} issues")
        
        return vulnerabilities
    
    def _check_vulnerability(self, vuln_data: Dict[str, Any], port_result: PortResult) -> bool:
        """
        Perform specific check for a vulnerability.
        
        Args:
            vuln_data: Vulnerability data from database
            port_result: Port scan result
            
        Returns:
            True if vulnerability is present
        """
        # Check banner for specific indicators
        banner = port_result.banner.lower()
        
        # FTP anonymous check
        if vuln_data["id"] == "FTP-001":
            return "anonymous" in banner or "230" in banner
        
        # Default checks - assume vulnerability present if service detected
        return True
    
    def _check_custom_vulnerabilities(self, port_result: PortResult) -> List[Vulnerability]:
        """
        Check for custom vulnerability patterns.
        
        Args:
            port_result: Port scan result
            
        Returns:
            List of detected vulnerabilities
        """
        vulns = []
        
        # Check for exposed admin interfaces
        if port_result.port in [8080, 8443, 9000, 9090]:
            if "admin" in port_result.banner.lower() or "management" in port_result.banner.lower():
                vulns.append(Vulnerability(
                    id="ADMIN-001",
                    name="Exposed Admin Interface",
                    severity=VulnerabilitySeverity.HIGH,
                    description="Administrative interface exposed on non-standard port.",
                    affected_port=port_result.port,
                    affected_service=port_result.service or "HTTP",
                    remediation="Restrict admin interface access to trusted IPs only.",
                    cvss_score=7.5,
                ))
        
        # Check for debug/development endpoints
        if port_result.port == 5000:  # Common Flask debug port
            vulns.append(Vulnerability(
                id="DEBUG-001",
                name="Development Server Exposed",
                severity=VulnerabilitySeverity.HIGH,
                description="Development/debug server detected on network.",
                affected_port=port_result.port,
                affected_service="HTTP",
                remediation="Do not run development servers in production.",
                cvss_score=7.5,
            ))
        
        return vulns
