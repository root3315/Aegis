"""
Core engine module for Aegis security scanner.

Orchestrates scanning operations, manages workflow, and coordinates components.
"""

import time
from datetime import datetime
from typing import Optional, Callable, Dict, Any, List
from pathlib import Path

from .config import ScanConfig, ScanMode, SecurityLevel
from .scanner import NetworkScanner, VulnerabilityScanner, ScanResult, PortState
from .reporter import ReportGenerator, ReportFormat
from .utils import (
    get_logger,
    resolve_hostname,
    validate_ip_address,
    validate_hostname,
    generate_scan_id,
    get_timestamp,
    ProgressBar,
)


class AegisEngine:
    """
    Main orchestration engine for Aegis security scanner.
    
    Coordinates all scanning operations and manages the complete
    security assessment workflow.
    
    Example:
        >>> config = ScanConfig(target="192.168.1.1")
        >>> engine = AegisEngine(config)
        >>> result = engine.run()
        >>> engine.generate_report(result, ReportFormat.HTML)
    """
    
    def __init__(self, config: ScanConfig) -> None:
        """
        Initialize Aegis engine.
        
        Args:
            config: Scan configuration parameters
        """
        self.config = config
        self.logger = get_logger("aegis.engine")
        self.scan_id = generate_scan_id()
        
        # Initialize components
        self.network_scanner = NetworkScanner(config)
        self.vuln_scanner = VulnerabilityScanner(config)
        self.reporter = ReportGenerator(config.output_dir)
        
        # State tracking
        self._is_running = False
        self._progress_callback: Optional[Callable[[int, int], None]] = None
    
    def validate_target(self) -> bool:
        """
        Validate the scan target.
        
        Returns:
            True if target is valid, False otherwise
        """
        target = self.config.target
        
        # Check if it's a valid IP
        if validate_ip_address(target):
            return True
        
        # Check if it's a valid hostname
        if validate_hostname(target):
            # Try to resolve
            resolved = resolve_hostname(target)
            if resolved:
                self.logger.info(f"Resolved {target} to {resolved}")
                return True
            self.logger.error(f"Failed to resolve hostname: {target}")
            return False
        
        self.logger.error(f"Invalid target format: {target}")
        return False
    
    def set_progress_callback(self, callback: Callable[[int, int], None]) -> None:
        """
        Set progress callback function.
        
        Args:
            callback: Function(current: int, total: int) for progress updates
        """
        self._progress_callback = callback
    
    def _progress_update(self, current: int, total: int) -> None:
        """Internal progress update handler."""
        if self._progress_callback:
            self._progress_callback(current, total)
    
    def run(self) -> ScanResult:
        """
        Execute the complete security scan.
        
        Returns:
            ScanResult containing all scan findings
            
        Raises:
            ValueError: If target is invalid
            RuntimeError: If scan is already running
        """
        if self._is_running:
            raise RuntimeError("Scan is already in progress")
        
        # Validate target
        if not self.validate_target():
            raise ValueError(f"Invalid scan target: {self.config.target}")
        
        self._is_running = True
        scan_start = get_timestamp()
        start_time = time.time()
        
        self.logger.info(f"Starting Aegis security scan (ID: {self.scan_id})")
        self.logger.info(f"Target: {self.config.target}")
        self.logger.info(f"Mode: {self.config.scan_mode.name}")
        self.logger.info(f"Security Level: {self.config.security_level.name}")
        
        try:
            # Phase 1: Port Scanning
            self.logger.info("Phase 1: Port Scanning")
            port_results = self.network_scanner.scan(self._progress_update)
            
            # Categorize results
            open_ports = [r for r in port_results if r.state == PortState.OPEN]
            closed_ports = [r for r in port_results if r.state == PortState.CLOSED]
            filtered_ports = [r for r in port_results if r.state == PortState.FILTERED]
            
            # Build services dictionary
            services = {
                r.port: r.service 
                for r in open_ports 
                if r.service
            }
            
            # Get resolved IP
            target_ip = resolve_hostname(self.config.target) or self.config.target
            
            # Phase 2: Vulnerability Assessment
            vulnerabilities = []
            if self.config.scan_mode in [ScanMode.VULNERABILITY_SCAN, ScanMode.FULL_AUDIT]:
                self.logger.info("Phase 2: Vulnerability Assessment")
                vulnerabilities = self.vuln_scanner.check_vulnerabilities(port_results)
            
            scan_end = get_timestamp()
            duration = time.time() - start_time
            
            # Build result
            result = ScanResult(
                target=self.config.target,
                target_ip=target_ip,
                scan_start=scan_start,
                scan_end=scan_end,
                duration=duration,
                ports_scanned=len(port_results),
                open_ports=open_ports,
                closed_ports=closed_ports,
                filtered_ports=filtered_ports,
                vulnerabilities=vulnerabilities,
                services=services,
            )
            
            self.logger.info(f"Scan completed in {duration:.2f}s")
            self._log_summary(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
        finally:
            self._is_running = False
    
    def _log_summary(self, result: ScanResult) -> None:
        """Log scan summary to console."""
        self.logger.info("=" * 50)
        self.logger.info("SCAN SUMMARY")
        self.logger.info("=" * 50)
        self.logger.info(f"Target: {result.target} ({result.target_ip})")
        self.logger.info(f"Duration: {result.duration:.2f}s")
        self.logger.info(f"Ports Scanned: {result.ports_scanned}")
        self.logger.info(f"Open Ports: {len(result.open_ports)}")
        self.logger.info(f"Vulnerabilities: {len(result.vulnerabilities)}")
        
        if result.vulnerabilities:
            severity_counts = {}
            for vuln in result.vulnerabilities:
                sev = vuln.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            self.logger.info("Vulnerability Breakdown:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    self.logger.info(f"  {sev}: {count}")
        
        self.logger.info("=" * 50)
    
    def generate_report(
        self,
        result: ScanResult,
        format: ReportFormat = ReportFormat.JSON,
        filename: Optional[str] = None,
    ) -> str:
        """
        Generate a scan report.
        
        Args:
            result: Scan result to report on
            format: Output format (JSON, HTML, Markdown, Text)
            filename: Optional custom filename
            
        Returns:
            Path to generated report file
        """
        self.logger.info(f"Generating {format.name} report")
        report_path = self.reporter.generate(result, format, filename)
        self.logger.info(f"Report saved to: {report_path}")
        return report_path
    
    def generate_all_reports(
        self,
        result: ScanResult,
        filename: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Generate reports in all supported formats.
        
        Args:
            result: Scan result to report on
            filename: Optional custom filename base
            
        Returns:
            Dictionary mapping format names to file paths
        """
        reports = {}
        
        for fmt in ReportFormat:
            try:
                path = self.generate_report(result, fmt, filename)
                reports[fmt.name] = path
            except Exception as e:
                self.logger.error(f"Failed to generate {fmt.name} report: {e}")
        
        return reports
    
    def stop(self) -> None:
        """Stop the current scan operation."""
        if self._is_running:
            self.logger.info("Stopping scan...")
            self.network_scanner.stop()
            self._is_running = False
    
    @classmethod
    def quick_scan(cls, target: str, ports: Optional[List[int]] = None) -> ScanResult:
        """
        Perform a quick scan with default settings.
        
        Args:
            target: Target IP or hostname
            ports: Optional list of ports (uses common ports if None)
            
        Returns:
            ScanResult from the quick scan
        """
        config = ScanConfig(
            target=target,
            ports=ports,
            security_level=SecurityLevel.NORMAL,
            timeout=1.0,
            threads=100,
            scan_mode=ScanMode.PORT_SCAN,
        )
        
        engine = cls(config)
        return engine.run()
    
    @classmethod
    def full_audit(cls, target: str) -> ScanResult:
        """
        Perform a full security audit.
        
        Args:
            target: Target IP or hostname
            
        Returns:
            ScanResult from the full audit
        """
        config = ScanConfig(
            target=target,
            security_level=SecurityLevel.NORMAL,
            timeout=2.0,
            threads=50,
            scan_mode=ScanMode.FULL_AUDIT,
            verbose=True,
        )
        
        engine = cls(config)
        return engine.run()
