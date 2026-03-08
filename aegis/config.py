"""
Configuration management for Aegis security scanner.

Handles scan parameters, security levels, and configuration validation.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict, Any
import json
from pathlib import Path


class SecurityLevel(Enum):
    """Security scanning intensity levels."""
    LOW = auto()      # Minimal packets, slowest detection
    NORMAL = auto()   # Balanced scanning
    AGGRESSIVE = auto()  # Fast, more detectable
    STEALTH = auto()  # Low detection probability


class ScanMode(Enum):
    """Available scanning modes."""
    PORT_SCAN = auto()
    VULNERABILITY_SCAN = auto()
    SERVICE_DETECTION = auto()
    FULL_AUDIT = auto()


@dataclass
class ScanConfig:
    """
    Configuration container for security scans.
    
    Attributes:
        target: Target IP address or hostname
        ports: List of ports to scan (None for all common ports)
        security_level: Scanning intensity level
        timeout: Socket timeout in seconds
        max_retries: Maximum retry attempts per port
        scan_mode: Type of scan to perform
        output_dir: Directory for report output
        verbose: Enable verbose logging
        threads: Number of concurrent threads
    """
    target: str
    ports: Optional[List[int]] = None
    security_level: SecurityLevel = SecurityLevel.NORMAL
    timeout: float = 2.0
    max_retries: int = 2
    scan_mode: ScanMode = ScanMode.PORT_SCAN
    output_dir: str = "./reports"
    verbose: bool = False
    threads: int = 50
    
    # Common port ranges
    COMMON_PORTS: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ])
    
    WELL_KNOWN_PORTS: List[int] = field(default_factory=lambda: list(range(1, 1025)))
    
    def __post_init__(self) -> None:
        """Validate and normalize configuration after initialization."""
        if not self.target or not self.target.strip():
            raise ValueError("Target cannot be empty")

        if self.ports is None:
            self.ports = self.COMMON_PORTS.copy()

        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")

        if self.max_retries < 0:
            raise ValueError("Max retries cannot be negative")

        if self.threads < 1:
            raise ValueError("Thread count must be at least 1")
    
    def get_ports(self) -> List[int]:
        """Return the configured port list."""
        return self.ports if self.ports else self.COMMON_PORTS
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "target": self.target,
            "ports": self.ports,
            "security_level": self.security_level.name,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "scan_mode": self.scan_mode.name,
            "output_dir": self.output_dir,
            "verbose": self.verbose,
            "threads": self.threads,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        """Create configuration from dictionary."""
        return cls(
            target=data["target"],
            ports=data.get("ports"),
            security_level=SecurityLevel[data.get("security_level", "NORMAL")],
            timeout=data.get("timeout", 2.0),
            max_retries=data.get("max_retries", 2),
            scan_mode=ScanMode[data.get("scan_mode", "PORT_SCAN")],
            output_dir=data.get("output_dir", "./reports"),
            verbose=data.get("verbose", False),
            threads=data.get("threads", 50),
        )
    
    @classmethod
    def from_file(cls, filepath: str) -> "ScanConfig":
        """Load configuration from JSON file."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {filepath}")
        
        with open(path, "r") as f:
            data = json.load(f)
        
        return cls.from_dict(data)
    
    def save(self, filepath: str) -> None:
        """Save configuration to JSON file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
