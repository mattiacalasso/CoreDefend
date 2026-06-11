# CoreDefend - Enterprise Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-Powered-4682B4?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Enterprise-grade vulnerability scanner inspired by Nessus, Qualys, and OpenVAS**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Compliance](#-compliance-frameworks) • [Architecture](#-architecture)

</div>

---

## Author

**Mattia Calasso**

---

## Overview

CoreDefend is an enterprise-grade automated vulnerability scanner designed for security professionals, penetration testers, and SOC teams. It combines the power of Nmap with CVE database lookups, compliance checking, and comprehensive reporting to provide complete security assessments through a modern web interface.

### Why CoreDefend?

| Feature | CoreDefend | Basic Scanners |
|---------|------------|----------------|
| Scan Presets | 6 optimized presets | Limited options |
| Compliance Frameworks | PCI-DSS, CIS, HIPAA, NIST | None |
| Asset Inventory | Automatic tracking | Manual |
| Remediation Tracking | Built-in workflow | External tools |
| Export Formats | PDF, CSV, JSON, HTML | PDF only |
| Scan History | Persistent storage | Session only |
| Speed Optimization | Parallel scanning | Sequential |

---

## Features

### Scan Presets

CoreDefend offers 6 optimized scan presets inspired by enterprise scanners:

| Preset | Timing | Ports | Features | Use Case |
|--------|--------|-------|----------|----------|
| **Ultra Fast** | T5 | Top 50 | Max parallelism, no DNS | Quick reconnaissance |
| **Quick Scan** | T4 | Top 100 | Optimized defaults | Daily scans |
| **Standard** | T4 | Top 1000 | Version detection | Regular assessments |
| **Full Scan** | T4 | Top 1000 | Scripts + versions | Comprehensive audit |
| **Stealth** | T2 | Top 100 | Low & slow | IDS evasion |
| **Custom** | User-defined | User-defined | All options | Advanced users |

### Vulnerability Analysis

- **Critical Port Detection**: Automatic flagging of high-risk ports (Telnet, SMB, RDP, etc.)
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW, INFO levels
- **CVSS Scoring**: Integration with NIST NVD for accurate risk scores
- **Actionable Recommendations**: Specific remediation guidance for each finding

### CVE Intelligence

- Automatic CVE lookup for detected service versions
- Integration with NIST NVD API (primary)
- Fallback to CIRCL CVE API
- CVSS score display and severity mapping
- Real-time threat intelligence

### Compliance Frameworks

CoreDefend includes built-in compliance checking for major security frameworks:

#### PCI-DSS 4.0
- Firewall Configuration (1.1)
- Default Credentials (2.1)
- Encryption in Transit (4.1)
- Vulnerability Management (6.1)
- Access Control (8.1)
- Logging & Monitoring (10.1)
- Vulnerability Scans (11.2)

#### CIS Controls v8
- Secure Configuration (4.1)
- Admin Privileges (4.2)
- Email Security (7.1)
- Network Security (12.1)
- Application Security (16.1)

#### HIPAA Security
- Access Control (164.312a)
- Integrity Controls (164.312c)
- Authentication (164.312d)
- Transmission Security (164.312e)

#### NIST 800-53
- Account Management (AC-2)
- Remote Access (AC-17)
- Least Functionality (CM-7)
- Vulnerability Scanning (RA-5)
- Boundary Protection (SC-7)

### Scan History

- Automatic saving of all scan results
- Risk score calculation for each scan
- Trend analysis across scans
- Comparison between assessments
- Persistent storage (survives restarts)

### Asset Inventory

- Automatic discovery and tracking of hosts
- Open ports and services database
- Last scan timestamp
- Findings count per asset
- Exportable asset list

### Remediation Tracking

- Add findings to remediation queue
- Status workflow: Pending → In Progress → Completed
- Notes and tracking per item
- Filter by status
- Priority management

### Export Formats

| Format | Content | Use Case |
|--------|---------|----------|
| **PDF** | Full formatted report | Executive reporting |
| **CSV** | Raw data export | Spreadsheet analysis |
| **JSON** | Structured data | API integration |
| **HTML** | Styled web report | Email sharing |

---

## Installation

### Prerequisites

1. **Python 3.10+** - Required for type hints and modern features
2. **Nmap** - Must be installed on the system

#### Installing Nmap

```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt update && sudo apt install nmap

# Fedora/RHEL
sudo dnf install nmap

# Windows
# Download from https://nmap.org/download.html
```

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/CoreDefend.git
cd CoreDefend
```

2. **Create a virtual environment**
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

---

## Usage

### Starting the Application

```bash
streamlit run app.py
```

The application will open in your default browser at `http://localhost:8501`

### Running with Elevated Privileges

Some scan types (like OS detection) require root/admin privileges:

```bash
# Linux/macOS
sudo streamlit run app.py

# Windows (Run as Administrator)
streamlit run app.py
```

### Interface Overview

CoreDefend features a tabbed interface with 5 main sections:

| Tab | Description |
|-----|-------------|
| **Scanner** | Configure and run vulnerability scans |
| **Compliance** | Check results against security frameworks |
| **History** | View past scans and trends |
| **Assets** | Manage discovered hosts |
| **Remediation** | Track vulnerability fixes |

### Quick Start Guide

1. Open the **Scanner** tab
2. Enter a target IP address or range (e.g., `192.168.1.1` or `192.168.1.0/24`)
3. Select a scan preset:
   - **Ultra Fast**: For quick reconnaissance
   - **Standard**: For regular assessments
   - **Full Scan**: For comprehensive audits
4. Toggle **CVE Lookup** for vulnerability intelligence
5. Click **START SCAN**
6. Review results in the dashboard
7. Check **Compliance** tab for framework assessments
8. Export reports in your preferred format

---

## Architecture

```
CoreDefend/
├── app.py                 # Main Streamlit application
├── scanner.py             # Nmap scanning module
├── analyzer.py            # Vulnerability analysis & CVE lookup
├── reporter.py            # PDF report generation
├── requirements.txt       # Python dependencies
├── README.md              # Documentation
└── coredefend_data/       # Persistent data storage
    ├── scan_history.json  # Scan history
    ├── assets.json        # Asset inventory
    └── remediation.json   # Remediation tracking
```

### Module Overview

| Module | Responsibility |
|--------|---------------|
| `app.py` | Web interface, tabs, visualization, compliance checking |
| `scanner.py` | Nmap wrapper, scan execution, result parsing |
| `analyzer.py` | Port risk assessment, CVE API queries, severity classification |
| `reporter.py` | PDF generation with ReportLab, report formatting |

### Data Flow

```
User Input → Scan Configuration
                    ↓
              scanner.py → Raw Scan Data
                    ↓
              analyzer.py → Vulnerability Report + CVE Data
                    ↓
              ┌─────────────────────────────────────┐
              │           app.py                    │
              │  ┌─────────────────────────────┐   │
              │  │ • Dashboard visualization    │   │
              │  │ • Compliance checking        │   │
              │  │ • History management         │   │
              │  │ • Asset inventory            │   │
              │  │ • Remediation tracking       │   │
              │  └─────────────────────────────┘   │
              └─────────────────────────────────────┘
                    ↓
              reporter.py → PDF/CSV/JSON/HTML Reports
```

---

## Speed Optimization

CoreDefend uses optimized Nmap parameters for maximum performance:

| Parameter | Purpose |
|-----------|---------|
| `-T4` / `-T5` | Aggressive timing |
| `-n` | Skip DNS resolution |
| `--min-parallelism 100` | Minimum parallel probes |
| `--max-parallelism 256` | Maximum parallel probes |
| `--max-retries 1-2` | Reduce retry attempts |
| `--min-hostgroup 64` | Group hosts for efficiency |
| `--max-rtt-timeout 100ms` | Aggressive timeout |

The **Ultra Fast** preset combines all optimizations for maximum speed.

---

## Critical Ports Reference

The scanner flags these high-risk ports with immediate alerts:

| Port | Service | Risk Level | Reason |
|------|---------|------------|--------|
| 21 | FTP | HIGH | Plaintext credentials |
| 22 | SSH | MEDIUM | Brute-force target |
| 23 | Telnet | CRITICAL | No encryption |
| 25 | SMTP | MEDIUM | Mail relay abuse |
| 53 | DNS | MEDIUM | DNS amplification |
| 110 | POP3 | HIGH | Plaintext email |
| 135 | MSRPC | HIGH | Windows exploitation |
| 139 | NetBIOS | HIGH | Legacy Windows |
| 143 | IMAP | HIGH | Plaintext email |
| 161 | SNMP | HIGH | Information disclosure |
| 443 | HTTPS | INFO | Web server |
| 445 | SMB | CRITICAL | Ransomware target |
| 1433 | MSSQL | CRITICAL | Database exposure |
| 3306 | MySQL | CRITICAL | Database exposure |
| 3389 | RDP | CRITICAL | Brute-force target |
| 5432 | PostgreSQL | CRITICAL | Database exposure |
| 5900 | VNC | CRITICAL | Remote access |
| 6379 | Redis | CRITICAL | Often unauthenticated |
| 27017 | MongoDB | CRITICAL | Often unauthenticated |

---

## API Integration

### NIST NVD API
- **Endpoint**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Usage**: Primary CVE lookup based on service/version keywords
- **Rate Limit**: Public access (consider API key for production)

### CIRCL CVE API
- **Endpoint**: `https://cve.circl.lu/api`
- **Usage**: Fallback when NVD returns no results
- **Rate Limit**: Public access

---

## Security Considerations

- **Authorization**: Only scan systems you own or have explicit permission to test
- **Network Impact**: Aggressive scans generate significant traffic
- **Rate Limiting**: CVE API calls are rate-limited to avoid blocks
- **Data Handling**: Scan results may contain sensitive information
- **Storage**: Local data files should be protected appropriately

---

## Requirements

```
streamlit>=1.28.0
pandas>=2.0.0
plotly>=5.18.0
python-nmap>=0.7.1
requests>=2.31.0
reportlab>=4.0.0
```

---

## Comparison with Enterprise Tools

| Feature | CoreDefend | Nessus | OpenVAS | Qualys |
|---------|------------|--------|---------|--------|
| Price | Free | $$$$ | Free | $$$$ |
| Scan Engine | Nmap | Proprietary | OpenVAS | Proprietary |
| CVE Database | NVD API | 130k+ plugins | 150k+ NVTs | Proprietary |
| Compliance | 4 frameworks | Many | Many | Many |
| Cloud-based | No | Optional | No | Yes |
| Ease of Use | High | High | Medium | High |
| Customization | High | Medium | High | Low |

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Nmap](https://nmap.org/) - The network scanning engine
- [python-nmap](https://pypi.org/project/python-nmap/) - Python bindings for Nmap
- [Streamlit](https://streamlit.io/) - The web framework
- [Plotly](https://plotly.com/) - Interactive visualizations
- [NIST NVD](https://nvd.nist.gov/) - CVE database
- [CIRCL](https://www.circl.lu/) - CVE API fallback

---

<div align="center">

**CoreDefend** - Enterprise Vulnerability Scanner

Created by **Mattia Calasso**

</div>
