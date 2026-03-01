# 🛡️ Aegis Security Scanner

**A professional, modular network security auditing tool for vulnerability scanning, port analysis, and security assessment.**

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Aegis is a comprehensive security scanning framework designed for network administrators, security professionals, and penetration testers. It provides a clean, modular architecture for performing network audits, vulnerability assessments, and security analysis.

Built with Python 3.8+, Aegis leverages concurrent scanning, intelligent service detection, and a built-in vulnerability database to deliver actionable security insights.

---

## Features

### 🔍 Network Scanning
- **TCP Port Scanning** - Fast, multi-threaded port discovery
- **Service Detection** - Automatic identification of running services
- **Banner Grabbing** - Capture service banners for fingerprinting
- **Configurable Timing** - Adjustable timeouts and retry logic

### 🐛 Vulnerability Assessment
- **Service-Based Detection** - Identify vulnerabilities by detected services
- **CVE Correlation** - Link findings to known CVE identifiers
- **Severity Classification** - CRITICAL, HIGH, MEDIUM, LOW, INFO ratings
- **Remediation Guidance** - Actionable fix recommendations

### 📊 Reporting
- **Multiple Formats** - JSON, HTML, Markdown, and plain text
- **Professional HTML Reports** - Styled, interactive reports
- **Machine-Readable JSON** - Easy integration with other tools
- **Custom Output Paths** - Configurable report destinations

### ⚡ Performance
- **Multi-threaded Scanning** - Configurable thread pools
- **Progress Tracking** - Real-time scan progress indicators
- **Graceful Interruption** - Clean handling of user interrupts

---

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Network access to target systems

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/aegis.git
cd aegis

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
python main.py --help
```

---

## Quick Start

### Basic Port Scan

```bash
python main.py 192.168.1.1
```

### Full Security Audit with HTML Report

```bash
python main.py scanme.nmap.org --mode full --format html
```

### Stealth Scan on Specific Ports

```bash
python main.py 10.0.0.1 -p 22,80,443 --level stealth
```

---

## Usage

### Command Line Interface

```
usage: aegis [-h] [-m {port,vuln,service,full}] [-l {low,normal,aggressive,stealth}]
             [-p PORTS] [-f {json,html,markdown,text,all}] [-o OUTPUT]
             [-t THREADS] [--timeout TIMEOUT] [-v] [--debug] [-q]
             target

Aegis Security Scanner - Network Security Auditing Tool

positional arguments:
  target                Target IP address or hostname to scan

optional arguments:
  -h, --help            Show help message and exit
  -m, --mode            Scan mode: port, vuln, service, or full (default: port)
  -l, --level           Security level (default: normal)
  -p, --ports           Comma-separated list of ports or ranges
  -f, --format          Report output format (default: text)
  -o, --output          Output directory for reports (default: ./reports)
  -t, --threads         Number of concurrent threads (default: 50)
  --timeout             Socket timeout in seconds (default: 2.0)
  -v, --verbose         Enable verbose output
  --debug               Enable debug logging
  -q, --quick           Quick scan with reduced timeout
```

### Scan Modes

| Mode | Description |
|------|-------------|
| `port` | Basic port scanning only |
| `vuln` | Vulnerability assessment on open ports |
| `service` | Service detection and fingerprinting |
| `full` | Complete security audit (recommended) |

### Security Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `low` | Minimal packets, slowest | Evasion-focused scans |
| `normal` | Balanced approach | General auditing |
| `aggressive` | Fast, more detectable | Internal networks |
| `stealth` | Low detection probability | External assessments |

---

## Architecture

```
aegis/
├── __init__.py      # Package initialization & exports
├── config.py        # Configuration management
├── utils.py         # Utility functions & helpers
├── scanner.py       # Network & vulnerability scanners
├── reporter.py      # Report generation (JSON, HTML, MD)
└── engine.py        # Core orchestration engine

main.py              # CLI entry point
requirements.txt     # Python dependencies
.gitignore           # Git ignore patterns
README.md            # This file
```

### Component Overview

#### `engine.py` - AegisEngine
The central orchestrator that coordinates all scanning operations. Manages the scan lifecycle, validates targets, and generates reports.

#### `scanner.py` - NetworkScanner, VulnerabilityScanner
- **NetworkScanner**: Performs TCP connect scans with configurable threading
- **VulnerabilityScanner**: Checks detected services against vulnerability database

#### `reporter.py` - ReportGenerator
Generates professional reports in multiple formats with consistent styling.

#### `config.py` - ScanConfig
Dataclass-based configuration with validation and serialization support.

#### `utils.py`
Logging, validation, formatting, and progress tracking utilities.

---

## API Reference

### Python API Usage

```python
from aegis import (
    AegisEngine,
    ScanConfig,
    SecurityLevel,
    ScanMode,
    ReportFormat,
)

# Create configuration
config = ScanConfig(
    target="192.168.1.1",
    ports=[22, 80, 443, 8080],
    security_level=SecurityLevel.NORMAL,
    scan_mode=ScanMode.FULL_AUDIT,
    threads=50,
    timeout=2.0,
)

# Initialize and run engine
engine = AegisEngine(config)
result = engine.run()

# Generate reports
engine.generate_report(result, ReportFormat.HTML)
engine.generate_report(result, ReportFormat.JSON)

# Or generate all formats at once
reports = engine.generate_all_reports(result)
```

### Quick Scan API

```python
from aegis import AegisEngine

# Quick scan with defaults
result = AegisEngine.quick_scan("192.168.1.1")

# Full audit
result = AegisEngine.full_audit("192.168.1.1")
```

### Accessing Results

```python
# Scan metadata
print(f"Target: {result.target}")
print(f"Duration: {result.duration:.2f}s")
print(f"Ports scanned: {result.ports_scanned}")

# Open ports
for port in result.open_ports:
    print(f"Port {port.port}: {port.service} ({port.state.name})")

# Vulnerabilities
for vuln in result.vulnerabilities:
    print(f"[{vuln.severity.value}] {vuln.name}")
    print(f"  CVE: {vuln.cve_id}")
    print(f"  Remediation: {vuln.remediation}")
```

---

## Configuration

### ScanConfig Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | str | Required | IP address or hostname |
| `ports` | List[int] | Common ports | Ports to scan |
| `security_level` | SecurityLevel | NORMAL | Scan intensity |
| `timeout` | float | 2.0 | Socket timeout (seconds) |
| `max_retries` | int | 2 | Retry attempts per port |
| `scan_mode` | ScanMode | PORT_SCAN | Type of scan |
| `output_dir` | str | ./reports | Report output directory |
| `verbose` | bool | False | Enable verbose logging |
| `threads` | int | 50 | Concurrent thread count |

### Loading Configuration from File

```python
from aegis import ScanConfig

# Load from JSON file
config = ScanConfig.from_file("scan_config.json")

# Save configuration
config.save("scan_config.json")
```

### Configuration File Format

```json
{
  "target": "192.168.1.1",
  "ports": [22, 80, 443, 3306, 5432],
  "security_level": "NORMAL",
  "timeout": 2.0,
  "max_retries": 2,
  "scan_mode": "FULL_AUDIT",
  "output_dir": "./reports",
  "verbose": true,
  "threads": 50
}
```

---

## Output Formats

### JSON Report
Machine-readable format suitable for integration with other tools and SIEM systems.

### HTML Report
Professional, styled report with:
- Executive summary dashboard
- Severity distribution charts
- Detailed vulnerability listings
- Open ports table

### Markdown Report
Documentation-friendly format for wikis and documentation systems.

### Text Report
Simple, terminal-friendly output for quick review.

---

## Security Considerations

### ⚠️ Legal Notice

**Only scan systems you own or have explicit permission to test.** Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

### Best Practices

1. **Authorization**: Obtain written permission before scanning
2. **Scope**: Define clear boundaries for testing
3. **Timing**: Schedule scans during maintenance windows
4. **Rate Limiting**: Use appropriate security levels to avoid DoS
5. **Logging**: Maintain audit trails of all scanning activities

### Detection Avoidance

For penetration testing scenarios requiring stealth:
- Use `--level stealth` for slower, less detectable scans
- Reduce thread count with `-t 10`
- Increase timeout values
- Consider using proxy chains for anonymity

---

## Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Run linting
flake8 aegis/
black --check aegis/
mypy aegis/
```

### Code Style

- Follow PEP 8 guidelines
- Use type hints for all functions
- Write docstrings for public APIs
- Maintain test coverage > 80%

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Write/update tests
4. Ensure all checks pass
5. Submit PR with description

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Aegis Security Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Support

For issues, feature requests, or questions:
- Open an issue on GitHub
- Check existing documentation
- Review the API reference

---

*Built with ❤️ by the Aegis Security Team*
