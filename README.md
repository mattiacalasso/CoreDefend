# 🛡️ CoreDefend - Automated Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-Powered-4682B4?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A professional, modular vulnerability scanner with a modern web interface.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [API Integration](#-api-integration)

</div>

---

## 📋 Overview

CoreDefend is an automated vulnerability scanner designed for security professionals and penetration testers. It combines the power of Nmap with CVE database lookups to provide comprehensive security assessments through an intuitive web interface.

**Key Highlights:**
- 🔍 Real-time network scanning with Nmap integration
- 🛡️ Automatic vulnerability identification and risk classification
- 📊 CVE lookup via NIST NVD and CIRCL APIs
- 📄 Professional PDF report generation
- 🎨 Modern, responsive Streamlit interface

---

## ✨ Features

### Network Scanning
- **Fast Scan**: Quick scan of the most common ports
- **Aggressive Scan**: Full OS detection and service version identification
- Support for single IPs, hostnames, and CIDR ranges
- Real-time progress indication

### Vulnerability Analysis
- **Critical Port Detection**: Automatic flagging of high-risk ports (Telnet, SMB, RDP, etc.)
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW, INFO levels
- **Actionable Recommendations**: Specific remediation guidance for each finding

### CVE Integration
- Automatic CVE lookup for detected service versions
- Integration with NIST NVD API (primary)
- Fallback to CIRCL CVE API
- CVSS score display and severity mapping

### Reporting
- **PDF Reports**: Professional, formatted vulnerability assessment reports
- **CSV Export**: Raw data export for further analysis
- Executive summary with risk overview
- Detailed findings with recommendations

---

## 🚀 Installation

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

## 💻 Usage

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

### Quick Start Guide

1. Enter a target IP address or range in the sidebar (e.g., `192.168.1.1` or `192.168.1.0/24`)
2. Select the scan type:
   - **Fast Scan**: For quick reconnaissance
   - **Aggressive**: For detailed service/OS detection
3. Click **Start Scan**
4. Review results in the dashboard tabs
5. Download the PDF report for documentation

---

## 🏗️ Architecture

```
CoreDefend/
├── app.py              # Streamlit GUI application
├── scanner.py          # Nmap scanning module
├── analyzer.py         # Vulnerability analysis & CVE lookup
├── reporter.py         # PDF report generation
├── requirements.txt    # Python dependencies
└── README.md           # Documentation
```

### Module Overview

| Module | Responsibility |
|--------|---------------|
| `app.py` | Web interface, user interaction, result visualization |
| `scanner.py` | Nmap wrapper, scan execution, result parsing |
| `analyzer.py` | Port risk assessment, CVE API queries, severity classification |
| `reporter.py` | PDF generation with ReportLab, report formatting |

### Data Flow

```
User Input → scanner.py → Raw Scan Data
                              ↓
                        analyzer.py → Vulnerability Report
                              ↓
                        reporter.py → PDF Report
                              ↓
                          app.py → Display Results
```

---

## 🔌 API Integration

### NIST NVD API
- **Endpoint**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Usage**: Primary CVE lookup based on service/version keywords
- **Rate Limit**: Public access (consider API key for production)

### CIRCL CVE API
- **Endpoint**: `https://cve.circl.lu/api`
- **Usage**: Fallback when NVD returns no results
- **Rate Limit**: Public access

---

## ⚠️ Critical Ports Reference

The scanner flags these high-risk ports with immediate alerts:

| Port | Service | Risk Level | Reason |
|------|---------|------------|--------|
| 21 | FTP | HIGH | Plaintext credentials |
| 23 | Telnet | CRITICAL | No encryption |
| 445 | SMB | CRITICAL | Ransomware target |
| 3389 | RDP | CRITICAL | Brute-force target |
| 3306 | MySQL | CRITICAL | Database exposure |
| 6379 | Redis | CRITICAL | Often unauthenticated |

See `analyzer.py` for the complete list of monitored ports.

---

## 🔒 Security Considerations

- **Authorization**: Only scan systems you own or have explicit permission to test
- **Network Impact**: Aggressive scans generate significant traffic
- **Rate Limiting**: CVE API calls are rate-limited to avoid blocks
- **Data Handling**: Scan results may contain sensitive information

---

## 🛠️ Development

### Code Style
- Type hints for all function signatures
- Docstrings following Google style
- Dataclasses for structured data
- Exception handling with custom error types

### Extending the Scanner

**Adding a new scan type:**
```python
# In scanner.py
SCAN_TYPES = {
    # ...existing types...
    "custom": {
        "arguments": "-sV --script=vuln",
        "description": "Custom vulnerability scripts"
    }
}
```

**Adding a new critical port:**
```python
# In analyzer.py
CRITICAL_PORTS = {
    # ...existing ports...
    8443: {
        "service": "HTTPS-Alt",
        "severity": Severity.MEDIUM,
        "message": "Alternative HTTPS port detected",
        "recommendation": "Verify certificate and TLS configuration"
    }
}
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Nmap](https://nmap.org/) - The network scanning engine
- [python-nmap](https://pypi.org/project/python-nmap/) - Python bindings for Nmap
- [Streamlit](https://streamlit.io/) - The web framework
- [NIST NVD](https://nvd.nist.gov/) - CVE database
- [CIRCL](https://www.circl.lu/) - CVE API fallback

---

<div align="center">

**Built with ❤️ for the security community**

</div>
