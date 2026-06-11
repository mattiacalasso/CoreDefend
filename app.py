"""
CoreDefend - Enterprise Vulnerability Scanner
Inspired by Nessus, Qualys, and OpenVAS

Features:
- Multi-preset scanning (Ultra Fast, Quick, Full, Custom)
- CVE Intelligence with CVSS scoring
- Compliance reporting (PCI-DSS, CIS, HIPAA)
- Scan history and asset inventory
- Multiple export formats (PDF, CSV, JSON, HTML)
- Remediation tracking
- Optimized parallel scanning

Usage:
    streamlit run app.py

Author: CoreDefend Security Team
License: MIT
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import os
import hashlib

# AI Integration
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

# Import local modules
from scanner import (
    NetworkScanner,
    NmapNotInstalledError,
    InsufficientPermissionsError,
    HostUnreachableError,
    NmapScannerError
)
from analyzer import VulnerabilityAnalyzer, Severity, VulnerabilityReport
from reporter import ReportGenerator


# ============================================================================
# CONFIGURATION
# ============================================================================

DATA_DIR = "coredefend_data"
SCAN_HISTORY_FILE = os.path.join(DATA_DIR, "scan_history.json")
ASSETS_FILE = os.path.join(DATA_DIR, "assets.json")
REMEDIATION_FILE = os.path.join(DATA_DIR, "remediation.json")

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)


# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="CoreDefend | Enterprise Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================================
# PROFESSIONAL DARK THEME CSS
# ============================================================================

st.markdown("""
<style>
    /* Hide default elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .stDeployButton {display: none;}
    [data-testid="stSidebar"] {display: none;}
    [data-testid="collapsedControl"] {display: none;}

    /* Global Dark Theme */
    .stApp {
        background: #0d0d0d;
    }

    /* Main Container */
    .main-container {
        background: #1a1a1a;
        border-radius: 16px;
        padding: 1.5rem;
        margin: 0.5rem;
    }

    /* Navigation Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: #1a1a1a;
        padding: 8px;
        border-radius: 12px;
    }

    .stTabs [data-baseweb="tab"] {
        background: #252525;
        border-radius: 8px;
        color: #888888;
        padding: 10px 20px;
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #ff6b35 0%, #f72c25 100%) !important;
        color: white !important;
    }

    /* Cards */
    .metric-card {
        background: #1e1e1e;
        border: 1px solid #2a2a2a;
        border-radius: 12px;
        padding: 1.25rem;
        text-align: center;
        transition: all 0.3s ease;
    }

    .metric-card:hover {
        border-color: #ff6b35;
        box-shadow: 0 0 20px rgba(255, 107, 53, 0.1);
    }

    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #ffffff;
    }

    .metric-label {
        font-size: 0.75rem;
        color: #666666;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 4px;
    }

    /* Section Headers */
    .section-header {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 1rem;
    }

    .section-icon {
        width: 8px;
        height: 8px;
        background: #ff6b35;
        border-radius: 2px;
    }

    .section-title {
        color: #ffffff;
        font-size: 1rem;
        font-weight: 600;
    }

    /* Data Cards */
    .data-card {
        background: #1e1e1e;
        border: 1px solid #2a2a2a;
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1rem;
    }

    /* Finding Cards */
    .finding-card {
        background: #252525;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.75rem;
        border-left: 4px solid;
    }

    .finding-critical { border-color: #ef4444; }
    .finding-high { border-color: #f97316; }
    .finding-medium { border-color: #eab308; }
    .finding-low { border-color: #22c55e; }
    .finding-info { border-color: #3b82f6; }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #f97316; }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: #eab308; }
    .badge-low { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
    .badge-info { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }

    /* Compliance Bars */
    .compliance-bar-container {
        height: 28px;
        background: #252525;
        border-radius: 6px;
        overflow: hidden;
        margin-bottom: 8px;
    }

    .compliance-bar {
        height: 100%;
        border-radius: 6px;
        display: flex;
        align-items: center;
        padding-left: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        color: white;
    }

    /* Input styling */
    .stTextInput > div > div > input {
        background-color: #252525 !important;
        border: 1px solid #333333 !important;
        color: #ffffff !important;
        border-radius: 8px !important;
    }

    .stTextInput > div > div > input:focus {
        border-color: #ff6b35 !important;
        box-shadow: 0 0 0 1px #ff6b35 !important;
    }

    .stSelectbox > div > div {
        background-color: #252525 !important;
        border: 1px solid #333333 !important;
        border-radius: 8px !important;
    }

    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #ff6b35 0%, #f72c25 100%) !important;
        color: white !important;
        font-weight: 600 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.75rem 2rem !important;
        transition: all 0.3s ease !important;
    }

    .stButton > button:hover {
        box-shadow: 0 4px 20px rgba(255, 107, 53, 0.4) !important;
        transform: translateY(-2px) !important;
    }

    /* Secondary Button */
    .stButton > button[kind="secondary"] {
        background: #252525 !important;
        border: 1px solid #333333 !important;
    }

    /* Progress Bar */
    .stProgress > div > div > div {
        background: linear-gradient(135deg, #ff6b35 0%, #f72c25 100%) !important;
    }

    /* Tables */
    .stDataFrame {
        background: #1e1e1e;
        border-radius: 8px;
    }

    /* History Item */
    .history-item {
        background: #252525;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    /* Asset Item */
    .asset-item {
        background: #252525;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.5rem;
        border-left: 4px solid #3b82f6;
    }

    /* Remediation Item */
    .remediation-item {
        background: #252525;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.5rem;
    }

    .remediation-pending { border-left: 4px solid #f97316; }
    .remediation-in-progress { border-left: 4px solid #3b82f6; }
    .remediation-completed { border-left: 4px solid #22c55e; }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #1a1a1a; }
    ::-webkit-scrollbar-thumb { background: #333333; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #444444; }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_severity_colors():
    """Return color mapping for severity levels."""
    return {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "INFO": "#3b82f6",
        "UNKNOWN": "#666666"
    }


def load_json_file(filepath, default=None):
    """Load JSON file or return default."""
    if default is None:
        default = []
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return default


def save_json_file(filepath, data):
    """Save data to JSON file."""
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        st.error(f"Error saving data: {e}")


def generate_scan_id():
    """Generate unique scan ID."""
    return hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8].upper()


# ============================================================================
# AI INTEGRATION (GROQ)
# ============================================================================

def get_groq_api_key():
    """Get Groq API key from secrets or environment."""
    # 1. Try Streamlit secrets (for Streamlit Cloud)
    try:
        if hasattr(st, 'secrets') and 'GROQ_API_KEY' in st.secrets:
            return st.secrets['GROQ_API_KEY']
    except Exception:
        pass

    # 2. Try environment variable (for local/VPS)
    env_key = os.getenv('GROQ_API_KEY')
    if env_key:
        return env_key

    return None


def get_groq_client():
    """Initialize Groq client."""
    if not GROQ_AVAILABLE:
        return None

    api_key = get_groq_api_key()
    if not api_key:
        return None

    try:
        return Groq(api_key=api_key)
    except Exception:
        return None


def analyze_with_ai(scan_result, vuln_report, analysis_type="full"):
    """Analyze scan results with AI."""
    client = get_groq_client()
    if not client:
        return None

    # Prepare scan data summary
    hosts_data = []
    for host in scan_result.hosts:
        open_ports = [{"port": p.port, "service": p.service, "version": p.version}
                      for p in host.ports if p.state == "open"]
        hosts_data.append({"ip": host.ip, "hostname": host.hostname, "ports": open_ports})

    findings_data = []
    for alert in vuln_report.port_alerts[:20]:  # Limit to top 20
        findings_data.append({
            "severity": alert.severity.value,
            "port": alert.port,
            "service": alert.service,
            "message": alert.message,
            "recommendation": alert.recommendation
        })

    cve_data = []
    if vuln_report.cve_findings:
        for cve in vuln_report.cve_findings[:10]:  # Limit to top 10
            cve_data.append({
                "cve_id": cve.cve_id,
                "severity": cve.severity.value,
                "cvss_score": cve.cvss_score,
                "description": cve.description[:200] if cve.description else ""
            })

    scan_summary = {
        "hosts": hosts_data,
        "findings": findings_data,
        "cves": cve_data,
        "stats": {
            "total_hosts": len(scan_result.hosts),
            "total_open_ports": sum(len(h["ports"]) for h in hosts_data),
            "critical_findings": len([f for f in findings_data if f["severity"] == "CRITICAL"]),
            "high_findings": len([f for f in findings_data if f["severity"] == "HIGH"]),
            "total_cves": len(cve_data)
        }
    }

    # Create prompt based on analysis type
    if analysis_type == "executive":
        prompt = f"""Sei un esperto di cybersecurity. Analizza questi risultati di una scansione di vulnerabilità e fornisci un EXECUTIVE SUMMARY in italiano.

DATI SCANSIONE:
{json.dumps(scan_summary, indent=2)}

Fornisci:
1. **Panoramica Rischio**: Valutazione generale del livello di rischio (Critico/Alto/Medio/Basso)
2. **Punti Critici**: I 3-5 problemi più urgenti da risolvere
3. **Impatto Business**: Potenziali conseguenze se non si interviene
4. **Raccomandazioni Prioritarie**: Azioni immediate da intraprendere

Usa un linguaggio chiaro e adatto a dirigenti non tecnici. Sii conciso ma completo."""

    elif analysis_type == "technical":
        prompt = f"""Sei un penetration tester esperto. Analizza questi risultati di scansione e fornisci un REPORT TECNICO DETTAGLIATO in italiano.

DATI SCANSIONE:
{json.dumps(scan_summary, indent=2)}

Fornisci:
1. **Attack Surface Analysis**: Analisi della superficie di attacco esposta
2. **Vulnerability Chain**: Possibili catene di attacco combinando le vulnerabilità trovate
3. **Exploitation Risk**: Per ogni vulnerabilità critica, indica la facilità di exploit
4. **Technical Remediation**: Comandi e configurazioni specifiche per risolvere i problemi
5. **Hardening Recommendations**: Suggerimenti per rafforzare la sicurezza

Sii tecnico e dettagliato, includi comandi specifici dove possibile."""

    elif analysis_type == "remediation":
        prompt = f"""Sei un security engineer. Crea un PIANO DI REMEDIATION dettagliato in italiano per queste vulnerabilità.

DATI SCANSIONE:
{json.dumps(scan_summary, indent=2)}

Per ogni vulnerabilità critica e alta, fornisci:
1. **Priorità**: Alta/Media/Bassa
2. **Difficoltà**: Facile/Media/Difficile
3. **Passi di Remediation**: Istruzioni step-by-step
4. **Comandi/Configurazioni**: Codice o configurazioni specifiche
5. **Verifica**: Come verificare che il fix sia stato applicato correttamente

Ordina per priorità (più urgenti prima)."""

    else:  # full analysis
        prompt = f"""Sei un esperto di cybersecurity. Analizza questi risultati di una scansione di vulnerabilità e fornisci un'ANALISI COMPLETA in italiano.

DATI SCANSIONE:
{json.dumps(scan_summary, indent=2)}

Fornisci un'analisi strutturata che includa:

## 1. Executive Summary
Breve panoramica per il management (3-4 frasi)

## 2. Risk Assessment
- Livello di rischio complessivo (Critico/Alto/Medio/Basso)
- Giustificazione del livello assegnato

## 3. Vulnerabilità Critiche
Analisi dettagliata delle vulnerabilità più gravi

## 4. Attack Vectors
Possibili scenari di attacco basati sulle vulnerabilità trovate

## 5. Priorità di Remediation
Lista ordinata delle azioni da intraprendere

## 6. Quick Wins
Azioni rapide che possono migliorare immediatamente la sicurezza

## 7. Raccomandazioni a Lungo Termine
Suggerimenti strategici per migliorare la postura di sicurezza

Sii professionale, dettagliato e actionable."""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "Sei un esperto di cybersecurity con anni di esperienza in vulnerability assessment e penetration testing. Rispondi sempre in italiano con analisi professionali e dettagliate."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=4000
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Errore nell'analisi AI: {str(e)}"


def chat_with_ai(user_question, scan_result, vuln_report):
    """Interactive chat about scan results."""
    client = get_groq_client()
    if not client:
        return "AI non disponibile. Verifica la configurazione dell'API key."

    # Prepare context
    context = {
        "hosts": len(scan_result.hosts),
        "open_ports": sum(len([p for p in h.ports if p.state == "open"]) for h in scan_result.hosts),
        "critical": len([a for a in vuln_report.port_alerts if a.severity == Severity.CRITICAL]),
        "high": len([a for a in vuln_report.port_alerts if a.severity == Severity.HIGH]),
        "findings": [{"severity": a.severity.value, "port": a.port, "message": a.message[:100]}
                     for a in vuln_report.port_alerts[:15]]
    }

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": f"""Sei un assistente di cybersecurity esperto. L'utente ha appena eseguito una scansione di vulnerabilità con questi risultati:

{json.dumps(context, indent=2)}

Rispondi alle domande dell'utente in italiano, basandoti su questi dati. Sii preciso e professionale."""},
                {"role": "user", "content": user_question}
            ],
            temperature=0.4,
            max_tokens=2000
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Errore: {str(e)}"


# ============================================================================
# SESSION STATE
# ============================================================================

def init_session_state():
    """Initialize session state variables."""
    defaults = {
        'scan_result': None,
        'vuln_report': None,
        'is_scanning': False,
        'current_page': 'scanner',
        'scan_history': load_json_file(SCAN_HISTORY_FILE, []),
        'assets': load_json_file(ASSETS_FILE, {}),
        'remediation': load_json_file(REMEDIATION_FILE, [])
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# ============================================================================
# SCAN PRESETS (Optimized like Nessus/Qualys)
# ============================================================================

SCAN_PRESETS = {
    "ultra_fast": {
        "name": "Ultra Fast",
        "description": "Fastest scan - Top 50 ports, maximum parallelism",
        "timing": 5,
        "port_mode": "top",
        "top_ports": 50,
        "port_range": "",
        "os_detection": False,
        "version_detection": False,
        "script_scan": False,
        "skip_host_discovery": True,
        "extra_args": "-n --max-retries 1 --min-parallelism 100 --max-parallelism 256 --min-hostgroup 64 --max-rtt-timeout 100ms"
    },
    "quick": {
        "name": "Quick Scan",
        "description": "Fast scan - Top 100 ports with optimization",
        "timing": 4,
        "port_mode": "fast",
        "top_ports": 100,
        "port_range": "",
        "os_detection": False,
        "version_detection": False,
        "script_scan": False,
        "skip_host_discovery": False,
        "extra_args": "-n --max-retries 2 --min-parallelism 50"
    },
    "standard": {
        "name": "Standard",
        "description": "Balanced scan - Top 1000 ports with version detection",
        "timing": 4,
        "port_mode": "top",
        "top_ports": 1000,
        "port_range": "",
        "os_detection": False,
        "version_detection": True,
        "script_scan": False,
        "skip_host_discovery": False,
        "extra_args": "-n --max-retries 2"
    },
    "full": {
        "name": "Full Scan",
        "description": "Comprehensive scan - All common ports with scripts",
        "timing": 4,
        "port_mode": "top",
        "top_ports": 1000,
        "port_range": "",
        "os_detection": False,
        "version_detection": True,
        "script_scan": True,
        "skip_host_discovery": False,
        "extra_args": "-n"
    },
    "stealth": {
        "name": "Stealth",
        "description": "Low and slow - Evade detection",
        "timing": 2,
        "port_mode": "top",
        "top_ports": 100,
        "port_range": "",
        "os_detection": False,
        "version_detection": False,
        "script_scan": False,
        "skip_host_discovery": False,
        "extra_args": "--max-rate 10 --scan-delay 1s"
    },
    "custom": {
        "name": "Custom",
        "description": "Configure your own scan parameters",
        "timing": 4,
        "port_mode": "fast",
        "top_ports": 100,
        "port_range": "",
        "os_detection": False,
        "version_detection": False,
        "script_scan": False,
        "skip_host_discovery": False,
        "extra_args": ""
    }
}


# ============================================================================
# COMPLIANCE FRAMEWORKS
# ============================================================================

COMPLIANCE_FRAMEWORKS = {
    "PCI-DSS": {
        "name": "PCI-DSS 4.0",
        "description": "Payment Card Industry Data Security Standard",
        "checks": [
            {"id": "1.1", "name": "Firewall Configuration", "ports": [22, 23, 3389], "severity": "HIGH"},
            {"id": "2.1", "name": "Default Credentials", "services": ["ftp", "telnet", "ssh"], "severity": "CRITICAL"},
            {"id": "4.1", "name": "Encryption in Transit", "ports": [80, 21, 23], "severity": "HIGH"},
            {"id": "6.1", "name": "Vulnerability Management", "check": "cve_count", "severity": "CRITICAL"},
            {"id": "8.1", "name": "Access Control", "ports": [22, 3389, 5900], "severity": "MEDIUM"},
            {"id": "10.1", "name": "Logging & Monitoring", "ports": [514, 1514], "severity": "MEDIUM"},
            {"id": "11.2", "name": "Vulnerability Scans", "check": "scan_complete", "severity": "HIGH"},
        ]
    },
    "CIS": {
        "name": "CIS Controls v8",
        "description": "Center for Internet Security Controls",
        "checks": [
            {"id": "4.1", "name": "Secure Configuration", "ports": [23, 21, 513], "severity": "HIGH"},
            {"id": "4.2", "name": "Admin Privileges", "ports": [22, 3389, 5985], "severity": "MEDIUM"},
            {"id": "7.1", "name": "Email Security", "ports": [25, 110, 143], "severity": "MEDIUM"},
            {"id": "12.1", "name": "Network Security", "ports": [161, 162, 69], "severity": "HIGH"},
            {"id": "16.1", "name": "Application Security", "check": "script_vulns", "severity": "HIGH"},
        ]
    },
    "HIPAA": {
        "name": "HIPAA Security",
        "description": "Health Insurance Portability and Accountability Act",
        "checks": [
            {"id": "164.312(a)", "name": "Access Control", "ports": [22, 3389, 5900], "severity": "HIGH"},
            {"id": "164.312(c)", "name": "Integrity Controls", "check": "integrity", "severity": "MEDIUM"},
            {"id": "164.312(d)", "name": "Authentication", "services": ["ftp", "telnet"], "severity": "CRITICAL"},
            {"id": "164.312(e)", "name": "Transmission Security", "ports": [80, 21, 23, 110], "severity": "HIGH"},
        ]
    },
    "NIST": {
        "name": "NIST 800-53",
        "description": "NIST Security and Privacy Controls",
        "checks": [
            {"id": "AC-2", "name": "Account Management", "ports": [389, 636, 3268], "severity": "MEDIUM"},
            {"id": "AC-17", "name": "Remote Access", "ports": [22, 3389, 5900, 5985], "severity": "HIGH"},
            {"id": "CM-7", "name": "Least Functionality", "check": "open_ports", "severity": "MEDIUM"},
            {"id": "RA-5", "name": "Vulnerability Scanning", "check": "vuln_assessment", "severity": "HIGH"},
            {"id": "SC-7", "name": "Boundary Protection", "ports": [23, 21, 513, 514], "severity": "HIGH"},
        ]
    }
}


# ============================================================================
# BUILD NMAP ARGUMENTS
# ============================================================================

def build_nmap_arguments(config: dict) -> str:
    """Build optimized nmap command arguments."""
    args = []

    # Timing template
    args.append(f"-T{config['timing']}")

    # Port selection
    if config['port_mode'] == "fast":
        args.append("-F")
    elif config['port_mode'] == "top":
        args.append(f"--top-ports {config['top_ports']}")
    elif config['port_mode'] == "range" and config.get('port_range'):
        args.append(f"-p {config['port_range']}")
    elif config['port_mode'] == "all":
        args.append("-p-")

    # Detection options
    if config.get('os_detection'):
        args.append("-O")
    if config.get('version_detection'):
        args.append("-sV")
    if config.get('script_scan'):
        args.append("-sC")
    if config.get('skip_host_discovery'):
        args.append("-Pn")

    # Extra optimization arguments
    if config.get('extra_args'):
        args.append(config['extra_args'])

    # Always verbose for progress
    args.append("-v")

    return " ".join(args)


# ============================================================================
# COMPLIANCE CHECKER
# ============================================================================

def check_compliance(scan_result, vuln_report, framework_id):
    """Check compliance against a specific framework."""
    framework = COMPLIANCE_FRAMEWORKS.get(framework_id)
    if not framework:
        return []

    results = []
    open_ports = set()
    services = set()

    for host in scan_result.hosts:
        for port in host.ports:
            if port.state == "open":
                open_ports.add(port.port)
                if port.service:
                    services.add(port.service.lower())

    cve_count = len(vuln_report.cve_findings) if vuln_report.cve_findings else 0

    for check in framework["checks"]:
        status = "PASS"
        details = ""

        if "ports" in check:
            found_ports = [p for p in check["ports"] if p in open_ports]
            if found_ports:
                status = "FAIL"
                details = f"Risky ports open: {', '.join(map(str, found_ports))}"
            else:
                details = "No risky ports detected"

        elif "services" in check:
            found_services = [s for s in check["services"] if s in services]
            if found_services:
                status = "FAIL"
                details = f"Insecure services: {', '.join(found_services)}"
            else:
                details = "No insecure services detected"

        elif check.get("check") == "cve_count":
            if cve_count > 0:
                status = "FAIL" if cve_count > 5 else "WARN"
                details = f"{cve_count} CVEs detected"
            else:
                details = "No CVEs detected"

        elif check.get("check") == "scan_complete":
            status = "PASS"
            details = "Vulnerability scan completed"

        elif check.get("check") == "open_ports":
            if len(open_ports) > 20:
                status = "WARN"
                details = f"{len(open_ports)} ports open - review for necessity"
            else:
                details = f"{len(open_ports)} ports open"

        results.append({
            "id": check["id"],
            "name": check["name"],
            "severity": check["severity"],
            "status": status,
            "details": details
        })

    return results


# ============================================================================
# SAVE SCAN TO HISTORY
# ============================================================================

def save_scan_to_history(target, scan_result, vuln_report, preset_name):
    """Save scan results to history."""
    scan_id = generate_scan_id()

    # Prepare scan data
    scan_data = {
        "id": scan_id,
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "preset": preset_name,
        "hosts_count": len(scan_result.hosts),
        "open_ports": sum(len([p for p in h.ports if p.state == "open"]) for h in scan_result.hosts),
        "critical_count": len([a for a in vuln_report.port_alerts if a.severity == Severity.CRITICAL]),
        "high_count": len([a for a in vuln_report.port_alerts if a.severity == Severity.HIGH]),
        "medium_count": len([a for a in vuln_report.port_alerts if a.severity == Severity.MEDIUM]),
        "cve_count": len(vuln_report.cve_findings) if vuln_report.cve_findings else 0,
        "risk_score": calculate_risk_score(vuln_report)
    }

    # Load and update history
    history = load_json_file(SCAN_HISTORY_FILE, [])
    history.insert(0, scan_data)
    history = history[:50]  # Keep last 50 scans
    save_json_file(SCAN_HISTORY_FILE, history)

    # Update assets
    update_assets(scan_result, vuln_report)

    return scan_id


def calculate_risk_score(vuln_report):
    """Calculate overall risk score (0-100)."""
    critical = len([a for a in vuln_report.port_alerts if a.severity == Severity.CRITICAL])
    high = len([a for a in vuln_report.port_alerts if a.severity == Severity.HIGH])
    medium = len([a for a in vuln_report.port_alerts if a.severity == Severity.MEDIUM])
    low = len([a for a in vuln_report.port_alerts if a.severity == Severity.LOW])

    # Weighted score
    score = 100 - (critical * 25 + high * 15 + medium * 8 + low * 3)
    return max(0, min(100, score))


def update_assets(scan_result, vuln_report):
    """Update asset inventory."""
    assets = load_json_file(ASSETS_FILE, {})

    for host in scan_result.hosts:
        host_key = host.ip

        open_ports = [{"port": p.port, "service": p.service, "version": p.version}
                      for p in host.ports if p.state == "open"]

        # Get findings for this host
        findings = []
        for alert in vuln_report.port_alerts:
            findings.append({
                "severity": alert.severity.value,
                "port": alert.port,
                "message": alert.message
            })

        assets[host_key] = {
            "ip": host.ip,
            "hostname": host.hostname,
            "last_scan": datetime.now().isoformat(),
            "open_ports": open_ports,
            "findings_count": len(findings),
            "os_guess": host.os_guess if hasattr(host, 'os_guess') else None
        }

    save_json_file(ASSETS_FILE, assets)


# ============================================================================
# REMEDIATION TRACKING
# ============================================================================

def add_remediation_item(finding, scan_id):
    """Add item to remediation tracking."""
    remediation = load_json_file(REMEDIATION_FILE, [])

    item = {
        "id": generate_scan_id(),
        "scan_id": scan_id,
        "created": datetime.now().isoformat(),
        "severity": finding.severity.value,
        "port": finding.port,
        "service": finding.service,
        "message": finding.message,
        "recommendation": finding.recommendation,
        "status": "pending",
        "notes": ""
    }

    remediation.insert(0, item)
    save_json_file(REMEDIATION_FILE, remediation)


def update_remediation_status(item_id, status, notes=""):
    """Update remediation item status."""
    remediation = load_json_file(REMEDIATION_FILE, [])

    for item in remediation:
        if item["id"] == item_id:
            item["status"] = status
            item["notes"] = notes
            item["updated"] = datetime.now().isoformat()
            break

    save_json_file(REMEDIATION_FILE, remediation)


# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

def export_to_json(scan_result, vuln_report):
    """Export results to JSON."""
    data = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "tool": "CoreDefend Enterprise Scanner"
        },
        "hosts": [],
        "findings": [],
        "cve_findings": []
    }

    for host in scan_result.hosts:
        host_data = {
            "ip": host.ip,
            "hostname": host.hostname,
            "ports": [{"port": p.port, "state": p.state, "service": p.service, "version": p.version}
                      for p in host.ports]
        }
        data["hosts"].append(host_data)

    for alert in vuln_report.port_alerts:
        data["findings"].append({
            "severity": alert.severity.value,
            "port": alert.port,
            "service": alert.service,
            "message": alert.message,
            "recommendation": alert.recommendation
        })

    if vuln_report.cve_findings:
        for cve in vuln_report.cve_findings:
            data["cve_findings"].append({
                "cve_id": cve.cve_id,
                "severity": cve.severity.value,
                "cvss_score": cve.cvss_score,
                "description": cve.description
            })

    return json.dumps(data, indent=2)


def export_to_html(scan_result, vuln_report):
    """Export results to HTML report."""
    critical = len([a for a in vuln_report.port_alerts if a.severity == Severity.CRITICAL])
    high = len([a for a in vuln_report.port_alerts if a.severity == Severity.HIGH])
    medium = len([a for a in vuln_report.port_alerts if a.severity == Severity.MEDIUM])

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CoreDefend Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a1a; color: #fff; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #ff6b35, #f72c25); padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; font-size: 2rem; }}
        .header p {{ margin: 5px 0 0; opacity: 0.9; }}
        .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }}
        .metric {{ background: #252525; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 2rem; font-weight: bold; }}
        .metric-label {{ color: #888; font-size: 0.8rem; text-transform: uppercase; }}
        .critical {{ color: #ef4444; }}
        .high {{ color: #f97316; }}
        .medium {{ color: #eab308; }}
        .section {{ background: #252525; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .section h2 {{ margin-top: 0; border-bottom: 2px solid #ff6b35; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #1a1a1a; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
        .badge-critical {{ background: rgba(239,68,68,0.2); color: #ef4444; }}
        .badge-high {{ background: rgba(249,115,22,0.2); color: #f97316; }}
        .badge-medium {{ background: rgba(234,179,8,0.2); color: #eab308; }}
        .badge-low {{ background: rgba(34,197,94,0.2); color: #22c55e; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CoreDefend Security Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{len(scan_result.hosts)}</div>
                <div class="metric-label">Hosts Scanned</div>
            </div>
            <div class="metric">
                <div class="metric-value critical">{critical}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric">
                <div class="metric-value high">{high}</div>
                <div class="metric-label">High</div>
            </div>
            <div class="metric">
                <div class="metric-value medium">{medium}</div>
                <div class="metric-label">Medium</div>
            </div>
        </div>

        <div class="section">
            <h2>Open Ports</h2>
            <table>
                <tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr>
"""

    for host in scan_result.hosts:
        for port in host.ports:
            if port.state == "open":
                html += f"<tr><td>{host.ip}</td><td>{port.port}</td><td>{port.service}</td><td>{port.version or '-'}</td></tr>"

    html += """
            </table>
        </div>

        <div class="section">
            <h2>Security Findings</h2>
            <table>
                <tr><th>Severity</th><th>Port</th><th>Finding</th><th>Recommendation</th></tr>
"""

    for alert in vuln_report.port_alerts:
        sev_class = alert.severity.value.lower()
        html += f"""<tr>
            <td><span class="badge badge-{sev_class}">{alert.severity.value}</span></td>
            <td>{alert.port}</td>
            <td>{alert.message}</td>
            <td>{alert.recommendation}</td>
        </tr>"""

    html += """
            </table>
        </div>
    </div>
</body>
</html>
"""
    return html


# ============================================================================
# RENDER FUNCTIONS
# ============================================================================

def render_header():
    """Render the main header."""
    st.markdown(f"""
    <div style="padding: 10px 0 20px 0;">
        <div style="font-size: 2rem; font-weight: 700; color: #ffffff;">COREDEFEND</div>
        <div style="font-size: 0.9rem; color: #ff6b35;">Enterprise Vulnerability Scanner • {datetime.now().strftime('%B %Y')}</div>
        <div style="font-size: 0.75rem; color: #666; margin-top: 4px;">by Mattia Calasso</div>
    </div>
    """, unsafe_allow_html=True)


def render_scanner_tab():
    """Render the main scanner tab."""
    col_title, col_help = st.columns([4, 1])

    with col_title:
        st.markdown("""
        <div class="section-header">
            <div class="section-icon"></div>
            <span class="section-title">Scan Configuration</span>
        </div>
        """, unsafe_allow_html=True)

    with col_help:
        with st.popover("📖 Guide"):
            st.markdown("""
            **Target Formats:**

            | Format | Example |
            |--------|---------|
            | Single IP | `192.168.1.1` |
            | Hostname | `example.com` |
            | CIDR | `192.168.1.0/24` |
            | IP Range | `192.168.1.1-50` |
            | Multiple | `192.168.1.1,192.168.1.5` |

            **Scan Presets:**

            - **Ultra Fast**: Top 50 ports, max speed
            - **Quick**: Top 100 ports, optimized
            - **Standard**: Top 1000 + version detection
            - **Full**: Scripts + version detection
            - **Stealth**: Low & slow, IDS evasion
            - **Custom**: Configure manually

            **Tips:**
            - Enable **CVE Lookup** for vulnerability intelligence
            - Use **Ultra Fast** for quick reconnaissance
            - Use **Full Scan** for comprehensive audits
            - OS Detection requires `sudo`
            """)

    # Target and Preset Selection
    col1, col2, col3 = st.columns([3, 2, 1])

    with col1:
        target = st.text_input(
            "Target",
            placeholder="Enter IP, hostname, or CIDR (e.g., 192.168.1.0/24)",
            label_visibility="collapsed"
        )

    with col2:
        preset_key = st.selectbox(
            "Preset",
            options=list(SCAN_PRESETS.keys()),
            format_func=lambda x: f"{SCAN_PRESETS[x]['name']} - {SCAN_PRESETS[x]['description'][:30]}...",
            label_visibility="collapsed"
        )

    with col3:
        analyze_cve = st.toggle("CVE Lookup", value=True)

    preset = SCAN_PRESETS[preset_key].copy()

    # Custom options
    if preset_key == "custom":
        with st.expander("Custom Configuration", expanded=True):
            col1, col2 = st.columns(2)

            with col1:
                st.markdown('<p style="color: #ff6b35; font-weight: 600; font-size: 0.85rem;">PORT SELECTION</p>', unsafe_allow_html=True)
                port_mode = st.radio(
                    "Ports",
                    ["fast", "top", "range", "all"],
                    format_func=lambda x: {"fast": "Fast (100)", "top": "Top N", "range": "Custom", "all": "All 65535"}.get(x),
                    horizontal=True,
                    label_visibility="collapsed"
                )
                preset["port_mode"] = port_mode

                if port_mode == "top":
                    preset["top_ports"] = st.slider("Top ports", 50, 5000, 1000)
                elif port_mode == "range":
                    preset["port_range"] = st.text_input("Port range", "22,80,443,8080")

                preset["timing"] = st.select_slider("Timing", [1, 2, 3, 4, 5], value=4,
                    format_func=lambda x: f"T{x}")

            with col2:
                st.markdown('<p style="color: #ff6b35; font-weight: 600; font-size: 0.85rem;">DETECTION</p>', unsafe_allow_html=True)
                preset["version_detection"] = st.checkbox("Version Detection (-sV)", value=True)
                preset["script_scan"] = st.checkbox("Script Scan (-sC)", value=False)
                preset["os_detection"] = st.checkbox("OS Detection (-O) ⚠️ sudo", value=False)
                preset["skip_host_discovery"] = st.checkbox("Skip Discovery (-Pn)", value=False)

    # Start Scan Button
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        start_btn = st.button("🚀 START SCAN", type="primary", use_container_width=True, disabled=not target)

    # Execute Scan
    if start_btn and target:
        execute_scan(target, preset, preset_key, analyze_cve)

    # Display Results
    if st.session_state.scan_result and st.session_state.vuln_report and not st.session_state.is_scanning:
        render_scan_results()


def execute_scan(target, preset, preset_name, analyze_cve):
    """Execute the vulnerability scan."""
    st.session_state.is_scanning = True

    progress_container = st.container()
    with progress_container:
        st.markdown('<div class="data-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #ff6b35; font-weight: 600;">SCANNING IN PROGRESS</p>', unsafe_allow_html=True)
        progress_bar = st.progress(0)
        status_text = st.empty()
        st.markdown('</div>', unsafe_allow_html=True)

    def update_progress(percent, task):
        progress_bar.progress(min(percent, 100))
        status_text.text(task)

    try:
        nmap_args = build_nmap_arguments(preset)
        update_progress(5, "Initializing scanner...")

        scanner = NetworkScanner()
        scan_result = scanner.scan_with_progress(target, custom_arguments=nmap_args, progress_callback=update_progress)

        update_progress(90, "Analyzing results...")

        analyzer = VulnerabilityAnalyzer()
        all_ports = [p for h in scan_result.hosts for p in h.ports]

        if analyze_cve:
            vuln_report = analyzer.generate_report(all_ports)
        else:
            vuln_report = VulnerabilityReport(port_alerts=analyzer.analyze_ports(all_ports))

        # Save to history
        scan_id = save_scan_to_history(target, scan_result, vuln_report, preset_name)

        st.session_state.scan_result = scan_result
        st.session_state.vuln_report = vuln_report
        st.session_state.is_scanning = False

        progress_container.empty()
        st.success(f"Scan completed! ID: {scan_id}")
        st.rerun()

    except NmapNotInstalledError:
        st.error("Nmap not installed. Install from https://nmap.org/download.html")
    except InsufficientPermissionsError:
        st.error("Insufficient permissions. Run with sudo for OS detection.")
    except HostUnreachableError:
        st.error(f"Host {target} unreachable. Check network connectivity.")
    except NmapScannerError as e:
        st.error(f"Scan error: {e}")
    finally:
        st.session_state.is_scanning = False


def render_scan_results():
    """Render scan results."""
    res = st.session_state.scan_result
    rep = st.session_state.vuln_report

    # Metrics Row
    total_hosts = len(res.hosts)
    open_ports = sum(len([p for p in h.ports if p.state == "open"]) for h in res.hosts)
    critical = len([a for a in rep.port_alerts if a.severity == Severity.CRITICAL])
    high = len([a for a in rep.port_alerts if a.severity == Severity.HIGH])
    medium = len([a for a in rep.port_alerts if a.severity == Severity.MEDIUM])
    risk_score = calculate_risk_score(rep)

    cols = st.columns(6)
    metrics = [
        (total_hosts, "Hosts", "#3b82f6"),
        (open_ports, "Open Ports", "#8b5cf6"),
        (critical, "Critical", "#ef4444"),
        (high, "High", "#f97316"),
        (medium, "Medium", "#eab308"),
        (f"{risk_score}%", "Risk Score", "#22c55e" if risk_score > 70 else "#f97316" if risk_score > 40 else "#ef4444")
    ]

    for col, (value, label, color) in zip(cols, metrics):
        with col:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color: {color};">{value}</div>
                <div class="metric-label">{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Two columns layout
    col1, col2 = st.columns([1.5, 1])

    with col1:
        # Findings
        st.markdown("""
        <div class="section-header">
            <div class="section-icon"></div>
            <span class="section-title">Security Findings</span>
        </div>
        """, unsafe_allow_html=True)

        for alert in rep.port_alerts[:10]:
            sev = alert.severity.value.lower()
            st.markdown(f"""
            <div class="finding-card finding-{sev}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="badge badge-{sev}">{alert.severity.value}</span>
                    <span style="color: #888; font-size: 0.8rem;">Port {alert.port}/{alert.service}</span>
                </div>
                <p style="color: #fff; margin: 8px 0 4px; font-size: 0.9rem;">{alert.message}</p>
                <p style="color: #666; font-size: 0.8rem; margin: 0;">💡 {alert.recommendation}</p>
            </div>
            """, unsafe_allow_html=True)

    with col2:
        # Services Chart
        st.markdown("""
        <div class="section-header">
            <div class="section-icon"></div>
            <span class="section-title">Exposed Services</span>
        </div>
        """, unsafe_allow_html=True)

        services = [p.service for h in res.hosts for p in h.ports if p.state == "open" and p.service]
        if services:
            df = pd.Series(services).value_counts().head(8).reset_index()
            df.columns = ['Service', 'Count']

            fig = go.Figure(go.Bar(
                x=df['Count'], y=df['Service'], orientation='h',
                marker_color='#ff6b35', text=df['Count'], textposition='inside'
            ))
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=0, r=0, t=0, b=0), height=250, showlegend=False,
                xaxis=dict(showgrid=True, gridcolor='#2a2a2a', tickfont=dict(color='#888')),
                yaxis=dict(showgrid=False, tickfont=dict(color='#fff'))
            )
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Export Section
    st.markdown("""
    <div class="section-header">
        <div class="section-icon"></div>
        <span class="section-title">Export Results</span>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        pdf_bytes = ReportGenerator().generate(res, rep)
        st.download_button("📄 PDF Report", pdf_bytes,
            f"CoreDefend_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf", "application/pdf", use_container_width=True)

    with col2:
        csv_data = pd.DataFrame([
            {"Host": h.ip, "Port": p.port, "Service": p.service, "Version": p.version or "-"}
            for h in res.hosts for p in h.ports if p.state == "open"
        ]).to_csv(index=False)
        st.download_button("📊 CSV Export", csv_data,
            f"CoreDefend_{datetime.now().strftime('%Y%m%d_%H%M')}.csv", "text/csv", use_container_width=True)

    with col3:
        json_data = export_to_json(res, rep)
        st.download_button("🔧 JSON Export", json_data,
            f"CoreDefend_{datetime.now().strftime('%Y%m%d_%H%M')}.json", "application/json", use_container_width=True)

    with col4:
        html_data = export_to_html(res, rep)
        st.download_button("🌐 HTML Report", html_data,
            f"CoreDefend_{datetime.now().strftime('%Y%m%d_%H%M')}.html", "text/html", use_container_width=True)


def render_compliance_tab():
    """Render compliance checking tab."""
    st.markdown("""
    <div class="section-header">
        <div class="section-icon"></div>
        <span class="section-title">Compliance Assessment</span>
    </div>
    """, unsafe_allow_html=True)

    if not st.session_state.scan_result:
        st.info("Run a scan first to check compliance.")
        return

    # Framework selection
    selected_frameworks = st.multiselect(
        "Select Compliance Frameworks",
        options=list(COMPLIANCE_FRAMEWORKS.keys()),
        default=["PCI-DSS", "CIS"],
        format_func=lambda x: COMPLIANCE_FRAMEWORKS[x]["name"]
    )

    for fw_id in selected_frameworks:
        framework = COMPLIANCE_FRAMEWORKS[fw_id]
        results = check_compliance(st.session_state.scan_result, st.session_state.vuln_report, fw_id)

        passed = len([r for r in results if r["status"] == "PASS"])
        total = len(results)
        score = int((passed / total) * 100) if total > 0 else 0

        st.markdown(f"""
        <div class="data-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <div>
                    <h3 style="color: #fff; margin: 0;">{framework['name']}</h3>
                    <p style="color: #888; margin: 0; font-size: 0.85rem;">{framework['description']}</p>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 2rem; font-weight: bold; color: {'#22c55e' if score >= 80 else '#f97316' if score >= 50 else '#ef4444'};">{score}%</div>
                    <div style="color: #888; font-size: 0.75rem;">{passed}/{total} Passed</div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        for result in results:
            status_color = {"PASS": "#22c55e", "FAIL": "#ef4444", "WARN": "#f97316"}.get(result["status"], "#888")
            st.markdown(f"""
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; background: #252525; border-radius: 6px; margin-bottom: 6px;">
                <div>
                    <span style="color: #ff6b35; font-weight: 600;">{result['id']}</span>
                    <span style="color: #fff; margin-left: 10px;">{result['name']}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <span style="color: #888; font-size: 0.8rem;">{result['details']}</span>
                    <span style="background: {status_color}22; color: {status_color}; padding: 4px 12px; border-radius: 4px; font-weight: 600; font-size: 0.75rem;">{result['status']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)


def render_history_tab():
    """Render scan history tab."""
    col1, col2 = st.columns([4, 1])

    with col1:
        st.markdown("""
        <div class="section-header">
            <div class="section-icon"></div>
            <span class="section-title">Scan History</span>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        if st.button("🗑️ Clear History", use_container_width=True):
            save_json_file(SCAN_HISTORY_FILE, [])
            save_json_file(ASSETS_FILE, {})
            st.success("History and assets cleared")
            st.rerun()

    history = load_json_file(SCAN_HISTORY_FILE, [])

    if not history:
        st.info("No scan history yet. Run your first scan!")
        return

    for scan in history[:20]:
        risk_color = "#22c55e" if scan.get("risk_score", 0) > 70 else "#f97316" if scan.get("risk_score", 0) > 40 else "#ef4444"

        st.markdown(f"""
        <div class="data-card" style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <div style="color: #ff6b35; font-weight: 600;">#{scan['id']}</div>
                <div style="color: #fff; font-size: 1.1rem;">{scan['target']}</div>
                <div style="color: #888; font-size: 0.8rem;">{scan['timestamp'][:16].replace('T', ' ')} • {scan['preset']}</div>
            </div>
            <div style="display: flex; gap: 20px; align-items: center;">
                <div style="text-align: center;">
                    <div style="color: #ef4444; font-size: 1.2rem; font-weight: bold;">{scan.get('critical_count', 0)}</div>
                    <div style="color: #888; font-size: 0.7rem;">CRITICAL</div>
                </div>
                <div style="text-align: center;">
                    <div style="color: #f97316; font-size: 1.2rem; font-weight: bold;">{scan.get('high_count', 0)}</div>
                    <div style="color: #888; font-size: 0.7rem;">HIGH</div>
                </div>
                <div style="text-align: center;">
                    <div style="color: {risk_color}; font-size: 1.5rem; font-weight: bold;">{scan.get('risk_score', 'N/A')}%</div>
                    <div style="color: #888; font-size: 0.7rem;">RISK SCORE</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)


def render_assets_tab():
    """Render asset inventory tab."""
    col1, col2 = st.columns([4, 1])

    with col1:
        st.markdown("""
        <div class="section-header">
            <div class="section-icon"></div>
            <span class="section-title">Asset Inventory</span>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        if st.button("🗑️ Clear Assets", use_container_width=True):
            save_json_file(ASSETS_FILE, {})
            st.success("Assets cleared")
            st.rerun()

    assets = load_json_file(ASSETS_FILE, {})

    if not assets:
        st.info("No assets discovered yet. Run a scan to populate inventory.")
        return

    # Summary metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Assets", len(assets))
    with col2:
        total_ports = sum(len(a.get("open_ports", [])) for a in assets.values())
        st.metric("Total Open Ports", total_ports)
    with col3:
        total_findings = sum(a.get("findings_count", 0) for a in assets.values())
        st.metric("Total Findings", total_findings)

    st.markdown("<br>", unsafe_allow_html=True)

    for ip, asset in assets.items():
        ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in asset.get("open_ports", [])[:5]])

        st.markdown(f"""
        <div class="asset-item">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div style="color: #fff; font-size: 1.1rem; font-weight: 600;">{asset['ip']}</div>
                    <div style="color: #888; font-size: 0.85rem;">{asset.get('hostname', 'Unknown hostname')}</div>
                </div>
                <div style="text-align: right;">
                    <div style="color: #3b82f6;">{len(asset.get('open_ports', []))} ports</div>
                    <div style="color: #888; font-size: 0.75rem;">Last: {asset.get('last_scan', 'N/A')[:10]}</div>
                </div>
            </div>
            <div style="color: #666; font-size: 0.8rem; margin-top: 8px;">Services: {ports_str or 'None'}</div>
        </div>
        """, unsafe_allow_html=True)


def render_remediation_tab():
    """Render remediation tracking tab."""
    col1, col2 = st.columns([4, 1])

    with col1:
        st.markdown("""
        <div class="section-header">
            <div class="section-icon"></div>
            <span class="section-title">Remediation Tracking</span>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        if st.button("🗑️ Clear Remediation", use_container_width=True):
            save_json_file(REMEDIATION_FILE, [])
            st.success("Remediation queue cleared")
            st.rerun()

    remediation = load_json_file(REMEDIATION_FILE, [])

    # Add from current findings
    if st.session_state.vuln_report:
        with st.expander("Add Findings to Remediation Queue"):
            for i, alert in enumerate(st.session_state.vuln_report.port_alerts[:10]):
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(f"**{alert.severity.value}** - Port {alert.port}: {alert.message[:50]}...")
                with col2:
                    if st.button("Add", key=f"add_rem_{i}"):
                        add_remediation_item(alert, "current")
                        st.success("Added to remediation queue")
                        st.rerun()

    if not remediation:
        st.info("No remediation items. Add findings from scan results.")
        return

    # Filter by status
    status_filter = st.selectbox("Filter by Status", ["All", "pending", "in-progress", "completed"])

    for item in remediation:
        if status_filter != "All" and item["status"] != status_filter:
            continue

        status_class = {"pending": "remediation-pending", "in-progress": "remediation-in-progress", "completed": "remediation-completed"}.get(item["status"], "")
        status_color = {"pending": "#f97316", "in-progress": "#3b82f6", "completed": "#22c55e"}.get(item["status"], "#888")

        st.markdown(f"""
        <div class="remediation-item {status_class}">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <span class="badge badge-{item['severity'].lower()}">{item['severity']}</span>
                    <span style="color: #888; margin-left: 10px;">Port {item['port']}/{item['service']}</span>
                </div>
                <span style="color: {status_color}; font-weight: 600; text-transform: uppercase; font-size: 0.75rem;">{item['status']}</span>
            </div>
            <p style="color: #fff; margin: 10px 0 5px;">{item['message']}</p>
            <p style="color: #888; font-size: 0.85rem; margin: 0;">💡 {item['recommendation']}</p>
        </div>
        """, unsafe_allow_html=True)

        # Status update buttons
        col1, col2, col3 = st.columns(3)
        with col1:
            if item["status"] != "pending" and st.button("⏳ Pending", key=f"pend_{item['id']}"):
                update_remediation_status(item["id"], "pending")
                st.rerun()
        with col2:
            if item["status"] != "in-progress" and st.button("🔄 In Progress", key=f"prog_{item['id']}"):
                update_remediation_status(item["id"], "in-progress")
                st.rerun()
        with col3:
            if item["status"] != "completed" and st.button("✅ Complete", key=f"done_{item['id']}"):
                update_remediation_status(item["id"], "completed")
                st.rerun()


def render_ai_tab():
    """Render AI Analysis tab."""
    st.markdown("""
    <div class="section-header">
        <div class="section-icon"></div>
        <span class="section-title">AI Security Analysis</span>
    </div>
    """, unsafe_allow_html=True)

    # Check if AI is available
    if not GROQ_AVAILABLE:
        st.error("Groq library non installata. Esegui: `pip install groq`")
        return

    if not get_groq_api_key():
        st.warning("API Key Groq non configurata. Configura GROQ_API_KEY nei secrets di Streamlit Cloud.")
        st.markdown("""
        **Come configurare:**
        1. Vai su [Streamlit Cloud](https://share.streamlit.io)
        2. Apri le impostazioni della tua app
        3. Aggiungi nei Secrets:
        ```toml
        GROQ_API_KEY = "la_tua_api_key"
        ```
        """)
        return

    if not st.session_state.scan_result or not st.session_state.vuln_report:
        st.info("Esegui prima una scansione per utilizzare l'analisi AI.")
        return

    # AI Analysis Options
    st.markdown("### Analisi Automatica")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("📊 Executive Summary", use_container_width=True):
            with st.spinner("Generazione Executive Summary..."):
                result = analyze_with_ai(st.session_state.scan_result, st.session_state.vuln_report, "executive")
                st.session_state.ai_result = result
                st.session_state.ai_type = "Executive Summary"

    with col2:
        if st.button("🔧 Report Tecnico", use_container_width=True):
            with st.spinner("Generazione Report Tecnico..."):
                result = analyze_with_ai(st.session_state.scan_result, st.session_state.vuln_report, "technical")
                st.session_state.ai_result = result
                st.session_state.ai_type = "Report Tecnico"

    with col3:
        if st.button("🛠️ Piano Remediation", use_container_width=True):
            with st.spinner("Generazione Piano Remediation..."):
                result = analyze_with_ai(st.session_state.scan_result, st.session_state.vuln_report, "remediation")
                st.session_state.ai_result = result
                st.session_state.ai_type = "Piano Remediation"

    with col4:
        if st.button("📋 Analisi Completa", use_container_width=True):
            with st.spinner("Generazione Analisi Completa..."):
                result = analyze_with_ai(st.session_state.scan_result, st.session_state.vuln_report, "full")
                st.session_state.ai_result = result
                st.session_state.ai_type = "Analisi Completa"

    # Display AI Result
    if 'ai_result' in st.session_state and st.session_state.ai_result:
        st.markdown(f"### {st.session_state.get('ai_type', 'Risultato AI')}")

        st.markdown(f"""
        <div class="data-card">
            <div style="color: #fff; line-height: 1.8;">
                {st.session_state.ai_result.replace(chr(10), '<br>')}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Export AI Report
        col1, col2 = st.columns([1, 3])
        with col1:
            st.download_button(
                "📥 Scarica Report AI",
                st.session_state.ai_result,
                f"CoreDefend_AI_{st.session_state.get('ai_type', 'Report')}_{datetime.now().strftime('%Y%m%d_%H%M')}.md",
                "text/markdown",
                use_container_width=True
            )

    # AI Chat
    st.markdown("---")
    st.markdown("### Chat con AI")
    st.markdown("Fai domande specifiche sui risultati della scansione.")

    # Initialize chat history
    if 'ai_chat_history' not in st.session_state:
        st.session_state.ai_chat_history = []

    # Chat input
    user_question = st.text_input(
        "Domanda",
        placeholder="Es: Quali sono le vulnerabilità più critiche? Come posso proteggere la porta 22?",
        key="ai_chat_input"
    )

    col1, col2 = st.columns([1, 4])
    with col1:
        send_btn = st.button("Invia", use_container_width=True)
    with col2:
        if st.button("Pulisci Chat", use_container_width=True):
            st.session_state.ai_chat_history = []
            st.rerun()

    if send_btn and user_question:
        with st.spinner("Elaborazione..."):
            response = chat_with_ai(user_question, st.session_state.scan_result, st.session_state.vuln_report)
            st.session_state.ai_chat_history.append({"role": "user", "content": user_question})
            st.session_state.ai_chat_history.append({"role": "assistant", "content": response})
            st.rerun()

    # Display chat history
    for msg in st.session_state.ai_chat_history:
        if msg["role"] == "user":
            st.markdown(f"""
            <div style="background: #3b82f6; color: white; padding: 12px 16px; border-radius: 12px; margin: 8px 0; margin-left: 20%;">
                <strong>Tu:</strong> {msg["content"]}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background: #252525; color: white; padding: 12px 16px; border-radius: 12px; margin: 8px 0; margin-right: 20%; border-left: 3px solid #ff6b35;">
                <strong>AI:</strong><br>{msg["content"].replace(chr(10), '<br>')}
            </div>
            """, unsafe_allow_html=True)


# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """Main application entry point."""
    init_session_state()

    # Header
    render_header()

    st.markdown("<br>", unsafe_allow_html=True)

    # Main Tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🔍 Scanner",
        "🤖 AI Analysis",
        "📋 Compliance",
        "📜 History",
        "💻 Assets",
        "🔧 Remediation"
    ])

    with tab1:
        render_scanner_tab()

    with tab2:
        render_ai_tab()

    with tab3:
        render_compliance_tab()

    with tab4:
        render_history_tab()

    with tab5:
        render_assets_tab()

    with tab6:
        render_remediation_tab()


if __name__ == "__main__":
    main()
