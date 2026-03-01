"""
Utility functions for Aegis security scanner.

Provides logging, formatting, validation, and helper functions.
"""

import logging
import socket
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pathlib import Path


class LogLevel(Enum):
    """Logging levels."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class Logger:
    """
    Centralized logging utility for Aegis.
    
    Provides consistent logging format across all modules.
    """
    
    _instance: Optional["Logger"] = None
    _logger: Optional[logging.Logger] = None
    
    def __new__(cls, *args, **kwargs) -> "Logger":
        """Singleton pattern for logger instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, name: str = "aegis", level: LogLevel = LogLevel.INFO) -> None:
        """Initialize logger if not already initialized."""
        if self._logger is None:
            self._logger = logging.getLogger(name)
            self._logger.setLevel(level.value)
            
            if not self._logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    "%(asctime)s | %(levelname)-8s | %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
                handler.setFormatter(formatter)
                self._logger.addHandler(handler)
    
    def get_logger(self) -> logging.Logger:
        """Return the configured logger instance."""
        return self._logger
    
    def set_level(self, level: LogLevel) -> None:
        """Set logging level."""
        self._logger.setLevel(level.value)
    
    def debug(self, msg: str) -> None:
        self._logger.debug(msg)
    
    def info(self, msg: str) -> None:
        self._logger.info(msg)
    
    def warning(self, msg: str) -> None:
        self._logger.warning(msg)
    
    def error(self, msg: str) -> None:
        self._logger.error(msg)
    
    def critical(self, msg: str) -> None:
        self._logger.critical(msg)


def get_logger(name: str = "aegis", level: LogLevel = LogLevel.INFO) -> logging.Logger:
    """Get a configured logger instance."""
    logger = Logger(name, level)
    return logger.get_logger()


def validate_ip_address(ip: str) -> bool:
    """
    Validate IPv4 address format.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IPv4 address, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname format.
    
    Args:
        hostname: Hostname to validate
        
    Returns:
        True if valid hostname, False otherwise
    """
    if len(hostname) > 255:
        return False
    
    if hostname.endswith("."):
        hostname = hostname[:-1]
    
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    for part in hostname.split("."):
        if not part or len(part) > 63:
            return False
        if not all(c in allowed for c in part.lower()):
            return False
        if part.startswith("-") or part.endswith("-"):
            return False
    
    return True


def resolve_hostname(target: str) -> Optional[str]:
    """
    Resolve hostname to IP address.
    
    Args:
        target: Hostname or IP address
        
    Returns:
        Resolved IP address or None if resolution fails
    """
    try:
        if validate_ip_address(target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def format_port_info(port: int, state: str, service: str = "") -> str:
    """
    Format port information for display.
    
    Args:
        port: Port number
        state: Port state (open/closed/filtered)
        service: Detected service name
        
    Returns:
        Formatted string representation
    """
    service_str = f" ({service})" if service else ""
    return f"Port {port:<6} {state:<10}{service_str}"


def format_bytes(size: int) -> str:
    """
    Format byte size to human-readable string.
    
    Args:
        size: Size in bytes
        
    Returns:
        Human-readable size string
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def generate_scan_id() -> str:
    """
    Generate unique scan identifier.
    
    Returns:
        Unique scan ID string
    """
    timestamp = datetime.now().isoformat()
    return hashlib.md5(timestamp.encode()).hexdigest()[:12]


def get_timestamp() -> str:
    """
    Get current timestamp in ISO format.
    
    Returns:
        Current timestamp string
    """
    return datetime.now().isoformat()


def get_date_string() -> str:
    """
    Get current date as string for filenames.
    
    Returns:
        Date string in YYYYMMDD format
    """
    return datetime.now().strftime("%Y%m%d")


def ensure_directory(path: str) -> Path:
    """
    Ensure directory exists, create if necessary.
    
    Args:
        path: Directory path
        
    Returns:
        Path object for the directory
    """
    dir_path = Path(path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split list into chunks of specified size.
    
    Args:
        items: List to split
        chunk_size: Size of each chunk
        
    Returns:
        List of chunks
    """
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


class ProgressBar:
    """Simple progress bar for CLI output."""
    
    def __init__(self, total: int, prefix: str = "Progress", width: int = 40) -> None:
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0
    
    def update(self, current: int) -> None:
        """Update progress bar to current position."""
        self.current = current
        self._display()
    
    def _display(self) -> None:
        """Render progress bar to stdout."""
        if self.total == 0:
            percent = 100.0
        else:
            percent = 100 * self.current / self.total
        
        filled = int(self.width * self.current / self.total) if self.total > 0 else self.width
        bar = "█" * filled + "░" * (self.width - filled)
        
        print(f"\r{self.prefix}: |{bar}| {percent:.1f}% ({self.current}/{self.total})", end="", flush=True)
        
        if self.current >= self.total:
            print()
    
    def finish(self) -> None:
        """Complete the progress bar."""
        self.current = self.total
        self._display()
