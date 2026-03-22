# 🛡️ KeyShield: Keylogger Detection & Defense Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Purpose](https://img.shields.io/badge/Purpose-Educational%20%2F%20Defensive%20Security-orange)
<img width="1410" height="1078" alt="image" src="https://github.com/user-attachments/assets/547c1223-a7a3-48ea-955c-5b1e85999f7a" />


A professional, cross-platform **keylogger detection and defense tool** built for cybersecurity education and system protection. KeyShield scans your system for indicators of keystroke logging activity and generates detailed security reports.

> ⚠️ **Educational & Defensive Use Only** This tool is designed to **detect and defend** against keyloggers, not to create them. Use responsibly and only on systems you own or have explicit permission to scan.

---

## 📸 Features

| Feature | Description |
|---|---|
| 🔍 Process Scanner | Detects suspicious processes with keylogging-related names or arguments |
| 📁 File Scanner | Finds suspicious log files in common directories |
| 🚀 Startup Scanner | Checks registry (Windows) and autostart folders (Linux) for malicious entries |
| 🌐 Network Scanner | Identifies suspicious outbound connections that may exfiltrate data |
| 🪝 Hook Detector | Detects active keyboard hook chains (Windows API) |
| 📊 Risk Analyzer | Computes a risk score and level from all findings |
| 📝 Report Generator | Saves detailed JSON + TXT reports with timestamps |
| 🖥️ GUI Dashboard | Tkinter-based dark-theme dashboard with live scan results |
| 📚 Education Panel | Built-in explanation of how keyloggers work |
| 🛡️ Defense Panel | Actionable defense and incident response guidance |

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/keyshield.git
cd keyshield
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Tool

**GUI Mode (recommended):**
```bash
python main.py
```

**CLI Mode:**
```bash
python main.py --cli
```

**CLI with custom output directory:**
```bash
python main.py --cli --output ./my_reports
```

---

## 📁 Project Structure

```
keyshield/
├── main.py                  # Entry point (GUI + CLI)
├── requirements.txt         # Python dependencies
├── README.md
├── src/
│   ├── detector.py          # Core scanning engine
│   └── gui.py               # Tkinter GUI dashboard
├── tests/
│   └── test_detector.py     # Unit tests (pytest)
└── reports/                 # Auto-generated scan reports
```

---

## 🧪 Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## 📊 Sample Report Output

```
======================================================================
  KeyShield - Keylogger Detection & Defense Tool v1.0
  Scan Date : 2024-01-15 14:32:07
  Platform  : Windows
======================================================================

RISK LEVEL : CLEAN  (Score: 0)
Summary    : No keylogging activity detected. System appears safe.
Findings   : 0 total  |  0 HIGH  |  0 MEDIUM  |  0 INFO
```

---

## 🔍 What It Detects

KeyShield scans for the following **Indicators of Compromise (IoCs)**:

### Suspicious Processes
Keywords: `keylog`, `hook`, `spy`, `sniff`, `capture`, `record`, `monitor`, `logger`, `pynput`, `pyxhook`, `keystroke`

### Suspicious Files
File names containing: `keylog`, `keystroke`, `typed`, `captured`, `input_log`, `keys`, `strokes`  
Extensions: `.log`, `.dat`, `.txt`, `.kl`

### Startup Persistence
- **Windows**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Linux**: `~/.config/autostart`, `/etc/xdg/autostart`, `/etc/init.d`

### Network Exfiltration
Outbound connections from unknown processes on ports: `21, 22, 25, 443, 4444, 6666, 9999, 31337`

---

## 📚 How Keyloggers Work (Educational)

Keyloggers operate by intercepting keyboard input at various levels:

| Type | Mechanism | Detection Difficulty |
|---|---|---|
| **Kernel-based** | OS device driver | Very Hard |
| **API-based** | `SetWindowsHookEx` (WH_KEYBOARD_LL) | Medium |
| **Form-grabbing** | Browser API hooks | Hard |
| **JavaScript** | Malicious browser scripts | Easy–Medium |
| **Hardware** | Physical USB/PS2 device | N/A (physical) |

See the **"How Keyloggers Work"** tab in the GUI for a full breakdown.

---

## 🛡️ Defense Recommendations

1. ✅ Keep OS and antivirus updated
2. ✅ Enable Two-Factor Authentication (TOTP) — keyloggers can't steal OTPs
3. ✅ Use a password manager (reduces typing of credentials)
4. ✅ Audit browser extensions regularly
5. ✅ Monitor startup programs
6. ✅ Run KeyShield scans periodically
7. ✅ Use a hardware security key (FIDO2/WebAuthn)

---

## ⚖️ Legal & Ethical Notice

This tool is intended **solely for defensive and educational purposes**:
- ✅ Scanning your own device
- ✅ Scanning devices you administer with user consent
- ✅ Security research in isolated lab environments
- ❌ Scanning devices without owner consent is **illegal** under computer fraud laws in most jurisdictions

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

Built as part of a cybersecurity internship project focused on **defensive security tooling**.
