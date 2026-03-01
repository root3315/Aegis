#!/usr/bin/env python3
"""
Aegis Security Scanner - Command Line Interface

A professional network security auditing tool for port scanning,
service detection, and vulnerability assessment.

Usage:
    python main.py <target> [options]
    python main.py 192.168.1.1 --mode full --format html
"""

import argparse
import sys
from typing import List, Optional

from aegis import (
    AegisEngine,
    ScanConfig,
    SecurityLevel,
    ScanMode,
    ReportFormat,
)
from aegis.utils import get_logger, LogLevel


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis Security Scanner - Network Security Auditing Tool",
        epilog="Examples:\n"
               "  python main.py 192.168.1.1\n"
               "  python main.py scanme.nmap.org --mode full --format html\n"
               "  python main.py 10.0.0.1 -p 22,80,443 --stealth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    # Target
    parser.add_argument(
        "target",
        type=str,
        help="Target IP address or hostname to scan",
    )
    
    # Scan mode
    parser.add_argument(
        "-m", "--mode",
        type=str,
        choices=["port", "vuln", "service", "full"],
        default="port",
        help="Scan mode: port, vuln, service, or full (default: port)",
    )
    
    # Security level
    parser.add_argument(
        "-l", "--level",
        type=str,
        choices=["low", "normal", "aggressive", "stealth"],
        default="normal",
        help="Security level (default: normal)",
    )
    
    # Ports
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default=None,
        help="Comma-separated list of ports or ranges (e.g., 22,80,443 or 1-1000)",
    )
    
    # Output format
    parser.add_argument(
        "-f", "--format",
        type=str,
        choices=["json", "html", "markdown", "text", "all"],
        default="text",
        help="Report output format (default: text)",
    )
    
    # Output directory
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./reports",
        help="Output directory for reports (default: ./reports)",
    )
    
    # Threads
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)",
    )
    
    # Timeout
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Socket timeout in seconds (default: 2.0)",
    )
    
    # Verbose
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    # Debug
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    
    # Quick scan
    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Quick scan with reduced timeout and common ports only",
    )
    
    return parser.parse_args()


def parse_ports(ports_str: str) -> Optional[List[int]]:
    """
    Parse port string to list of integers.
    
    Args:
        ports_str: Port string (e.g., "22,80,443" or "1-1000")
        
    Returns:
        List of port numbers or None for default
    """
    if not ports_str:
        return None
    
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    
    return sorted(set(ports))


def get_scan_mode(mode_str: str) -> ScanMode:
    """Convert mode string to ScanMode enum."""
    mode_map = {
        "port": ScanMode.PORT_SCAN,
        "vuln": ScanMode.VULNERABILITY_SCAN,
        "service": ScanMode.SERVICE_DETECTION,
        "full": ScanMode.FULL_AUDIT,
    }
    return mode_map.get(mode_str, ScanMode.PORT_SCAN)


def get_security_level(level_str: str) -> SecurityLevel:
    """Convert level string to SecurityLevel enum."""
    level_map = {
        "low": SecurityLevel.LOW,
        "normal": SecurityLevel.NORMAL,
        "aggressive": SecurityLevel.AGGRESSIVE,
        "stealth": SecurityLevel.STEALTH,
    }
    return level_map.get(level_str, SecurityLevel.NORMAL)


def get_report_format(format_str: str) -> Optional[ReportFormat]:
    """Convert format string to ReportFormat enum."""
    if format_str == "all":
        return None  # Signal to generate all formats
    
    format_map = {
        "json": ReportFormat.JSON,
        "html": ReportFormat.HTML,
        "markdown": ReportFormat.MARKDOWN,
        "text": ReportFormat.TEXT,
    }
    return format_map.get(format_str, ReportFormat.TEXT)


def main() -> int:
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    log_level = LogLevel.DEBUG if args.debug else LogLevel.INFO
    logger = get_logger("aegis", log_level)
    
    # Quick scan override
    if args.quick:
        logger.info("Quick scan mode enabled")
        result = AegisEngine.quick_scan(args.target)
        
        # Generate text report for quick scan
        engine = AegisEngine(ScanConfig(target=args.target))
        report_path = engine.generate_report(result, ReportFormat.TEXT)
        print(f"\nReport saved to: {report_path}")
        return 0
    
    # Parse configuration
    ports = parse_ports(args.ports)
    scan_mode = get_scan_mode(args.mode)
    security_level = get_security_level(args.level)
    
    # Create configuration
    config = ScanConfig(
        target=args.target,
        ports=ports,
        security_level=security_level,
        timeout=args.timeout,
        threads=args.threads,
        scan_mode=scan_mode,
        output_dir=args.output,
        verbose=args.verbose,
    )
    
    # Display banner
    print_banner()
    print(f"\n🎯 Target: {args.target}")
    print(f"📊 Mode: {scan_mode.name}")
    print(f"🔒 Security Level: {security_level.name}")
    print(f"🧵 Threads: {args.threads}")
    if ports:
        print(f"📡 Ports: {len(ports)} specified")
    print()
    
    # Create engine and run scan
    engine = AegisEngine(config)
    
    try:
        result = engine.run()
        
        # Generate reports
        report_format = get_report_format(args.format)
        
        if report_format is None:
            # Generate all formats
            reports = engine.generate_all_reports(result)
            print("\n📁 Reports generated:")
            for fmt, path in reports.items():
                print(f"   {fmt}: {path}")
        else:
            report_path = engine.generate_report(result, report_format)
            print(f"\n📁 Report saved to: {report_path}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        engine.stop()
        return 130
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def print_banner() -> None:
    """Print application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                    AEGIS SECURITY SCANNER                  ║
    ║                    Network Security Audit                   ║
    ║                         v1.0.0                              ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


if __name__ == "__main__":
    sys.exit(main())
