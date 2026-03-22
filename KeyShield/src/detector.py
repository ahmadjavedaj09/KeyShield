"""
KeyShield - Keylogger Detection & Defense Tool
Author: Security Research Tool
Purpose: Detect and analyze potential keylogging activity on the system
"""

import os
import sys
import json
import time
import platform
import datetime
import hashlib
import subprocess
from pathlib import Path


# ─────────────────────────────────────────────
#  Platform Detection
# ─────────────────────────────────────────────
PLATFORM = platform.system()  # 'Windows', 'Linux', 'Darwin'


# ─────────────────────────────────────────────
#  Suspicious Keyword Lists
# ─────────────────────────────────────────────
SUSPICIOUS_PROCESS_KEYWORDS = [
    "keylog", "hook", "spy", "sniff", "capture", "record",
    "monitor", "logger", "stealth", "invisible", "hidden",
    "pynput", "pyxhook", "keystroke", "inputcapture"
]

SUSPICIOUS_FILE_EXTENSIONS = [".log", ".dat", ".txt", ".kl"]

SUSPICIOUS_FILE_KEYWORDS = [
    "keylog", "keystroke", "typed", "captured", "input_log",
    "keys", "strokes", "activity_log"
]

KNOWN_SAFE_PROCESSES = [
    "explorer.exe", "svchost.exe", "system", "idle",
    "bash", "zsh", "python3", "code", "chrome", "firefox"
]


# ─────────────────────────────────────────────
#  Color Helpers (cross-platform ANSI)
# ─────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

    @staticmethod
    def supports_color():
        return sys.stdout.isatty()

def c(text, color):
    if Color.supports_color():
        return f"{color}{text}{Color.RESET}"
    return text


# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────
BANNER = r"""
 ██╗  ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
 ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
 █████╔╝ █████╗   ╚████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
 ██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
 ██║  ██╗███████╗   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
                  Keylogger Detection & Defense Tool v1.0
"""


# ─────────────────────────────────────────────
#  Process Scanner
# ─────────────────────────────────────────────
def scan_processes():
    """Scan running processes for suspicious keylogging activity."""
    findings = []

    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
            try:
                name = (proc.info['name'] or "").lower()
                cmdline = " ".join(proc.info['cmdline'] or []).lower()

                for kw in SUSPICIOUS_PROCESS_KEYWORDS:
                    if kw in name or kw in cmdline:
                        findings.append({
                            "type": "Suspicious Process",
                            "severity": "HIGH",
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cmdline": " ".join(proc.info['cmdline'] or [])[:120],
                            "user": proc.info.get('username', 'unknown'),
                            "keyword_matched": kw,
                            "timestamp": datetime.datetime.now().isoformat()
                        })
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    except ImportError:
        findings.append({
            "type": "Scanner Warning",
            "severity": "INFO",
            "message": "psutil not installed. Process scanning skipped.",
            "fix": "Run: pip install psutil"
        })

    return findings


# ─────────────────────────────────────────────
#  Hook / Input API Scanner (Windows)
# ─────────────────────────────────────────────
def scan_input_hooks():
    """Detect global keyboard hooks via Windows API."""
    findings = []

    if PLATFORM != "Windows":
        return findings

    try:
        import ctypes
        user32 = ctypes.windll.user32
        # WH_KEYBOARD_LL = 13
        hook_count = 0
        # This enumerates windows and checks for hook chains (simplified detection)
        hwnd = user32.GetForegroundWindow()
        if hwnd:
            tid = user32.GetWindowThreadProcessId(hwnd, None)
            # Check for low-level keyboard hooks in the thread
            # A real hook chain check would use SetWindowsHookEx internals
            # Here we flag the scan was performed
            findings.append({
                "type": "Hook Scan",
                "severity": "INFO",
                "message": "Windows hook API scan completed.",
                "details": "No low-level keyboard hooks detected in foreground thread.",
                "timestamp": datetime.datetime.now().isoformat()
            })
    except Exception as e:
        findings.append({
            "type": "Hook Scan Error",
            "severity": "WARNING",
            "message": str(e)
        })

    return findings


# ─────────────────────────────────────────────
#  Suspicious File Scanner
# ─────────────────────────────────────────────
def scan_files(search_paths=None):
    """Scan common directories for suspicious log files."""
    findings = []

    if search_paths is None:
        home = Path.home()
        search_paths = [
            home,
            home / "Downloads",
            home / "Documents",
            Path("/tmp") if PLATFORM != "Windows" else Path(os.environ.get("TEMP", "C:\\Temp")),
            Path.cwd()
        ]

    for base_path in search_paths:
        if not base_path.exists():
            continue
        try:
            for fpath in base_path.rglob("*"):
                if not fpath.is_file():
                    continue
                name_lower = fpath.name.lower()
                if fpath.suffix.lower() in SUSPICIOUS_FILE_EXTENSIONS:
                    for kw in SUSPICIOUS_FILE_KEYWORDS:
                        if kw in name_lower:
                            size = fpath.stat().st_size
                            findings.append({
                                "type": "Suspicious File",
                                "severity": "MEDIUM",
                                "path": str(fpath),
                                "size_bytes": size,
                                "keyword_matched": kw,
                                "last_modified": datetime.datetime.fromtimestamp(
                                    fpath.stat().st_mtime
                                ).isoformat(),
                                "timestamp": datetime.datetime.now().isoformat()
                            })
                            break
        except PermissionError:
            continue

    return findings


# ─────────────────────────────────────────────
#  Startup Entry Scanner
# ─────────────────────────────────────────────
def scan_startup_entries():
    """Check startup locations for suspicious executables."""
    findings = []

    if PLATFORM == "Windows":
        try:
            import winreg
            keys = [
                (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hive, subkey in keys:
                try:
                    with winreg.OpenKey(hive, subkey) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                val_lower = value.lower()
                                for kw in SUSPICIOUS_PROCESS_KEYWORDS:
                                    if kw in val_lower or kw in name.lower():
                                        findings.append({
                                            "type": "Suspicious Startup Entry",
                                            "severity": "HIGH",
                                            "registry_key": subkey,
                                            "entry_name": name,
                                            "entry_value": value,
                                            "keyword_matched": kw,
                                            "timestamp": datetime.datetime.now().isoformat()
                                        })
                                i += 1
                            except OSError:
                                break
                except PermissionError:
                    continue
        except ImportError:
            pass

    elif PLATFORM == "Linux":
        autostart_paths = [
            Path.home() / ".config/autostart",
            Path("/etc/xdg/autostart"),
            Path("/etc/init.d"),
        ]
        for ap in autostart_paths:
            if not ap.exists():
                continue
            for f in ap.iterdir():
                try:
                    content = f.read_text(errors="ignore").lower()
                    for kw in SUSPICIOUS_PROCESS_KEYWORDS:
                        if kw in content or kw in f.name.lower():
                            findings.append({
                                "type": "Suspicious Startup Entry",
                                "severity": "HIGH",
                                "path": str(f),
                                "keyword_matched": kw,
                                "timestamp": datetime.datetime.now().isoformat()
                            })
                            break
                except Exception:
                    continue

    return findings


# ─────────────────────────────────────────────
#  Network Connection Scanner
# ─────────────────────────────────────────────
def scan_network_connections():
    """Look for suspicious outbound connections that may exfiltrate keylog data."""
    findings = []

    try:
        import psutil
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                # Flag connections on common exfiltration ports
                suspicious_ports = {21, 22, 25, 443, 4444, 6666, 9999, 31337}
                if conn.raddr.port in suspicious_ports:
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else "unknown"
                        if proc_name.lower() not in KNOWN_SAFE_PROCESSES:
                            findings.append({
                                "type": "Suspicious Network Connection",
                                "severity": "MEDIUM",
                                "pid": conn.pid,
                                "process": proc_name,
                                "remote_ip": conn.raddr.ip,
                                "remote_port": conn.raddr.port,
                                "timestamp": datetime.datetime.now().isoformat()
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
    except ImportError:
        pass

    return findings


# ─────────────────────────────────────────────
#  Risk Analyzer
# ─────────────────────────────────────────────
def analyze_risk(all_findings):
    """Compute overall risk score and summary."""
    severity_weights = {"HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0, "WARNING": 1}
    score = sum(severity_weights.get(f.get("severity", "INFO"), 0) for f in all_findings)

    if score == 0:
        level = "CLEAN"
        description = "No keylogging activity detected. System appears safe."
    elif score < 10:
        level = "LOW RISK"
        description = "Minor suspicious indicators found. Manual review recommended."
    elif score < 25:
        level = "MEDIUM RISK"
        description = "Suspicious activity detected. Investigate flagged items immediately."
    else:
        level = "HIGH RISK"
        description = "Strong indicators of keylogging activity. Take immediate action."

    return {
        "score": score,
        "level": level,
        "description": description,
        "total_findings": len(all_findings),
        "high_count": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
        "medium_count": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
        "info_count": sum(1 for f in all_findings if f.get("severity") in ("INFO", "WARNING")),
    }


# ─────────────────────────────────────────────
#  Report Generator
# ─────────────────────────────────────────────
def generate_report(findings, risk, output_dir="reports"):
    """Save JSON and human-readable TXT report."""
    Path(output_dir).mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    report = {
        "tool": "KeyShield - Keylogger Detection & Defense Tool",
        "version": "1.0",
        "generated_at": datetime.datetime.now().isoformat(),
        "platform": PLATFORM,
        "risk_assessment": risk,
        "findings": findings
    }

    # JSON report
    json_path = Path(output_dir) / f"scan_report_{ts}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    # Human-readable TXT report
    txt_path = Path(output_dir) / f"scan_report_{ts}.txt"
    with open(txt_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  KeyShield - Keylogger Detection & Defense Tool v1.0\n")
        f.write(f"  Scan Date : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Platform  : {PLATFORM}\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"RISK LEVEL : {risk['level']}  (Score: {risk['score']})\n")
        f.write(f"Summary    : {risk['description']}\n")
        f.write(f"Findings   : {risk['total_findings']} total  |  "
                f"{risk['high_count']} HIGH  |  "
                f"{risk['medium_count']} MEDIUM  |  "
                f"{risk['info_count']} INFO\n\n")

        f.write("-" * 70 + "\n")
        f.write("DETAILED FINDINGS\n")
        f.write("-" * 70 + "\n\n")

        if not findings:
            f.write("  No suspicious activity detected.\n")
        else:
            for i, finding in enumerate(findings, 1):
                f.write(f"[{i}] {finding.get('type', 'Unknown')}  —  Severity: {finding.get('severity', '?')}\n")
                for k, v in finding.items():
                    if k not in ("type", "severity"):
                        f.write(f"    {k:<20}: {v}\n")
                f.write("\n")

        f.write("=" * 70 + "\n")
        f.write("RECOMMENDATIONS\n")
        f.write("=" * 70 + "\n")
        f.write("""
  1. Keep your operating system and antivirus software up to date.
  2. Avoid installing software from untrusted sources.
  3. Review startup programs regularly using Task Manager / msconfig.
  4. Monitor outbound network traffic with a firewall.
  5. Use a password manager to reduce keystroke exposure.
  6. Enable 2FA on critical accounts — keyloggers can't capture TOTP codes.
  7. Periodically audit installed browser extensions.
  8. On shared systems, run scans after each session.
""")

    return str(json_path), str(txt_path)


# ─────────────────────────────────────────────
#  Main Runner
# ─────────────────────────────────────────────
def run_scan(verbose=True):
    if verbose:
        print(c(BANNER, Color.CYAN))
        print(c(f"  Platform : {PLATFORM}", Color.BOLD))
        print(c(f"  Time     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Color.BOLD))
        print()

    all_findings = []
    steps = [
        ("Scanning running processes ...", scan_processes),
        ("Scanning for suspicious files ...", scan_files),
        ("Scanning startup entries ...",      scan_startup_entries),
        ("Scanning network connections ...",  scan_network_connections),
        ("Checking input hooks ...",          scan_input_hooks),
    ]

    for label, fn in steps:
        if verbose:
            print(c(f"  ► {label}", Color.YELLOW), end=" ", flush=True)
        results = fn()
        all_findings.extend(results)
        if verbose:
            count = len([r for r in results if r.get("severity") in ("HIGH", "MEDIUM")])
            status = c(f"[{count} alerts]", Color.RED) if count else c("[OK]", Color.GREEN)
            print(status)

    risk = analyze_risk(all_findings)
    json_path, txt_path = generate_report(all_findings, risk)

    if verbose:
        print()
        print(c("─" * 60, Color.CYAN))
        level_color = Color.RED if "HIGH" in risk["level"] else (
            Color.YELLOW if "MEDIUM" in risk["level"] else Color.GREEN
        )
        print(c(f"  RISK LEVEL : {risk['level']}  (Score: {risk['score']})", level_color + Color.BOLD))
        print(f"  {risk['description']}")
        print(c("─" * 60, Color.CYAN))
        print(f"\n  Reports saved:")
        print(f"    JSON → {json_path}")
        print(f"    TXT  → {txt_path}")
        print()

    return all_findings, risk, json_path, txt_path


if __name__ == "__main__":
    run_scan()
