"""
KeyShield GUI Dashboard
Tkinter-based graphical interface for the Keylogger Detection Tool
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.detector import run_scan, PLATFORM


# ─────────────────────────────────────────────
#  Theme
# ─────────────────────────────────────────────
BG        = "#0d1117"
BG2       = "#161b22"
BG3       = "#21262d"
ACCENT    = "#00d4aa"
RED       = "#f85149"
YELLOW    = "#e3b341"
GREEN     = "#3fb950"
FG        = "#e6edf3"
FG2       = "#8b949e"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Segoe UI", 10) if PLATFORM == "Windows" else ("Helvetica", 10)
FONT_BIG  = ("Segoe UI", 22, "bold") if PLATFORM == "Windows" else ("Helvetica", 22, "bold")


class KeyShieldGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("KeyShield — Keylogger Detection & Defense Tool")
        self.root.configure(bg=BG)
        self.root.geometry("960x680")
        self.root.resizable(True, True)

        self._build_ui()

    # ─── UI Construction ───────────────────────────────────────────────

    def _build_ui(self):
        # ── Header
        header = tk.Frame(self.root, bg=BG2, pady=14)
        header.pack(fill="x")

        tk.Label(header, text="🛡  KeyShield", font=FONT_BIG,
                 bg=BG2, fg=ACCENT).pack(side="left", padx=20)
        tk.Label(header, text="Keylogger Detection & Defense Tool  v1.0",
                 font=FONT_UI, bg=BG2, fg=FG2).pack(side="left")

        tk.Label(header, text=f"Platform: {PLATFORM}",
                 font=FONT_UI, bg=BG2, fg=FG2).pack(side="right", padx=20)

        # ── Risk Banner
        self.risk_frame = tk.Frame(self.root, bg=BG3, pady=10)
        self.risk_frame.pack(fill="x", padx=0)

        self.risk_label = tk.Label(self.risk_frame, text="Run a scan to assess your system",
                                   font=(FONT_UI[0], 12, "bold"), bg=BG3, fg=FG2)
        self.risk_label.pack()

        # ── Control Bar
        ctrl = tk.Frame(self.root, bg=BG, pady=10)
        ctrl.pack(fill="x", padx=16)

        self.scan_btn = tk.Button(
            ctrl, text="▶  Run Full Scan", font=(FONT_UI[0], 11, "bold"),
            bg=ACCENT, fg=BG, activebackground="#00b894", activeforeground=BG,
            bd=0, padx=20, pady=8, cursor="hand2", command=self._start_scan
        )
        self.scan_btn.pack(side="left")

        self.clear_btn = tk.Button(
            ctrl, text="✕  Clear", font=FONT_UI,
            bg=BG3, fg=FG2, activebackground=BG2, bd=0, padx=14, pady=8,
            cursor="hand2", command=self._clear
        )
        self.clear_btn.pack(side="left", padx=8)

        self.progress = ttk.Progressbar(ctrl, mode="indeterminate", length=200)
        self.progress.pack(side="left", padx=16)

        self.time_label = tk.Label(ctrl, text="", font=FONT_UI, bg=BG, fg=FG2)
        self.time_label.pack(side="right")

        # ── Stat Cards
        stats_frame = tk.Frame(self.root, bg=BG)
        stats_frame.pack(fill="x", padx=16, pady=(0, 8))

        self.card_total  = self._stat_card(stats_frame, "Total Findings", "—", FG2)
        self.card_high   = self._stat_card(stats_frame, "High Severity",  "—", RED)
        self.card_medium = self._stat_card(stats_frame, "Medium Severity","—", YELLOW)
        self.card_score  = self._stat_card(stats_frame, "Risk Score",     "—", ACCENT)

        # ── Notebook
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self._style_notebook()

        # Tab 1: Findings
        tab_findings = tk.Frame(nb, bg=BG)
        nb.add(tab_findings, text="  Findings  ")
        self._build_findings_tab(tab_findings)

        # Tab 2: Log
        tab_log = tk.Frame(nb, bg=BG)
        nb.add(tab_log, text="  Scan Log  ")
        self._build_log_tab(tab_log)

        # Tab 3: Education
        tab_edu = tk.Frame(nb, bg=BG)
        nb.add(tab_edu, text="  How Keyloggers Work  ")
        self._build_edu_tab(tab_edu)

        # Tab 4: Defense Tips
        tab_def = tk.Frame(nb, bg=BG)
        nb.add(tab_def, text="  Defense Tips  ")
        self._build_defense_tab(tab_def)

    def _stat_card(self, parent, label, value, color):
        f = tk.Frame(parent, bg=BG3, padx=20, pady=10)
        f.pack(side="left", expand=True, fill="x", padx=(0, 8))
        lbl = tk.Label(f, text=label, font=FONT_UI, bg=BG3, fg=FG2)
        lbl.pack()
        val = tk.Label(f, text=value, font=(FONT_UI[0], 20, "bold"), bg=BG3, fg=color)
        val.pack()
        return val

    def _style_notebook(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",       background=BG,  borderwidth=0)
        style.configure("TNotebook.Tab",   background=BG3, foreground=FG2,
                        padding=[12, 6], font=FONT_UI)
        style.map("TNotebook.Tab",
                  background=[("selected", BG2)],
                  foreground=[("selected", ACCENT)])
        style.configure("Treeview",        background=BG2, foreground=FG,
                        fieldbackground=BG2, rowheight=26, font=FONT_UI)
        style.configure("Treeview.Heading", background=BG3, foreground=ACCENT,
                        font=(FONT_UI[0], 10, "bold"))
        style.map("Treeview", background=[("selected", BG3)])

    def _build_findings_tab(self, parent):
        cols = ("severity", "type", "detail", "timestamp")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("severity",  text="Severity")
        self.tree.heading("type",      text="Finding Type")
        self.tree.heading("detail",    text="Detail")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.column("severity",  width=100, anchor="center")
        self.tree.column("type",      width=200)
        self.tree.column("detail",    width=460)
        self.tree.column("timestamp", width=160)

        sb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Tag colors
        self.tree.tag_configure("HIGH",    foreground=RED)
        self.tree.tag_configure("MEDIUM",  foreground=YELLOW)
        self.tree.tag_configure("LOW",     foreground=GREEN)
        self.tree.tag_configure("INFO",    foreground=FG2)
        self.tree.tag_configure("WARNING", foreground=YELLOW)

    def _build_log_tab(self, parent):
        self.log = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=FG, font=FONT_MONO,
            insertbackground=ACCENT, bd=0, padx=10, pady=10
        )
        self.log.pack(fill="both", expand=True)
        self.log.config(state="disabled")

    def _build_edu_tab(self, parent):
        content = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=FG, font=FONT_MONO,
            insertbackground=ACCENT, bd=0, padx=20, pady=20,
            wrap="word"
        )
        content.pack(fill="both", expand=True)

        edu_text = """
HOW KEYLOGGERS WORK — Educational Overview
═══════════════════════════════════════════════════════════════

1. WHAT IS A KEYLOGGER?
   A keylogger is software (or hardware) that records keystrokes
   made by a user, typically without their knowledge. The captured
   data may include passwords, messages, credit card numbers, and
   other sensitive information.

2. TYPES OF KEYLOGGERS
   ┌─────────────────────┬──────────────────────────────────────┐
   │ Type                │ How It Works                         │
   ├─────────────────────┼──────────────────────────────────────┤
   │ Kernel-based        │ Runs as a device driver; hardest to  │
   │                     │ detect; captures at OS level         │
   ├─────────────────────┼──────────────────────────────────────┤
   │ API-based           │ Uses OS hook APIs (e.g. Windows      │
   │                     │ SetWindowsHookEx with WH_KEYBOARD_LL)│
   ├─────────────────────┼──────────────────────────────────────┤
   │ Form-grabbing       │ Intercepts browser form submissions   │
   │                     │ before encryption is applied         │
   ├─────────────────────┼──────────────────────────────────────┤
   │ JavaScript-based    │ Runs in browser via malicious script  │
   ├─────────────────────┼──────────────────────────────────────┤
   │ Hardware            │ Physical device plugged between       │
   │                     │ keyboard and computer                │
   └─────────────────────┴──────────────────────────────────────┘

3. HOW DATA IS EXFILTRATED
   • Written to a local file (e.g. keylog.txt)
   • Emailed periodically to an attacker
   • Sent via HTTP POST to a remote server
   • Uploaded via FTP

4. HOW DETECTION WORKS (what this tool does)
   ✓ Scans running processes for suspicious names / keywords
   ✓ Checks startup registry entries (Windows) / autostart (Linux)
   ✓ Looks for suspicious log files in common directories
   ✓ Monitors network connections for unusual outbound traffic
   ✓ Checks for active keyboard hook chains (Windows API)

5. WHY THIS MATTERS
   Keyloggers are among the most dangerous attack tools because:
   • They operate silently in the background
   • They can capture credentials before encryption
   • They are often delivered via phishing or malicious software
   • Detection requires active monitoring

6. LEGAL & ETHICAL NOTE
   Installing keylogging software on any device without explicit
   written consent of ALL users is ILLEGAL in most jurisdictions
   under computer fraud and privacy laws.
"""
        content.insert("end", edu_text)
        content.config(state="disabled")

    def _build_defense_tab(self, parent):
        content = scrolledtext.ScrolledText(
            parent, bg=BG2, fg=FG, font=FONT_MONO,
            insertbackground=ACCENT, bd=0, padx=20, pady=20,
            wrap="word"
        )
        content.pack(fill="both", expand=True)

        defense_text = """
DEFENSE STRATEGIES AGAINST KEYLOGGERS
═══════════════════════════════════════════════════════════════

PREVENTION
  ✓ Keep OS, browsers, and antivirus fully updated
  ✓ Never install software from untrusted sources
  ✓ Use an ad-blocker and script-blocker in your browser
  ✓ Be cautious with email attachments and links (phishing)
  ✓ Audit browser extensions — remove anything unfamiliar
  ✓ On shared computers, use a live OS (USB boot)

AUTHENTICATION
  ✓ Enable Two-Factor Authentication (2FA / TOTP)
     → Keyloggers CANNOT capture one-time codes
  ✓ Use a password manager (reduces manual typing)
  ✓ Use hardware security keys (FIDO2/WebAuthn)
  ✓ Rotate passwords regularly for critical accounts

DETECTION
  ✓ Run this tool (KeyShield) periodically
  ✓ Monitor Task Manager for unknown processes
  ✓ Check startup programs regularly
  ✓ Use a network firewall to monitor outbound traffic
  ✓ Enable Windows Defender / ClamAV (Linux) real-time protection

INCIDENT RESPONSE (if keylogger is found)
  1. Disconnect from the internet immediately
  2. Document and preserve evidence (screenshots, reports)
  3. Boot from a clean USB live environment
  4. Run a full antivirus scan from external media
  5. Change ALL passwords from a known-clean device
  6. Enable 2FA on all accounts
  7. Report to your IT/security team or law enforcement
  8. Consider a full OS reinstall if compromise is confirmed

ENTERPRISE RECOMMENDATIONS
  ✓ Deploy Endpoint Detection & Response (EDR) solutions
  ✓ Use application whitelisting
  ✓ Implement Privileged Access Management (PAM)
  ✓ Monitor SIEM for hook-related Windows Event IDs
  ✓ Conduct regular security awareness training
"""
        content.insert("end", defense_text)
        content.config(state="disabled")

    # ─── Scan Logic ────────────────────────────────────────────────────

    def _start_scan(self):
        self.scan_btn.config(state="disabled")
        self.progress.start(10)
        self._log(f"\n{'═'*55}")
        self._log(f"  Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._log(f"{'═'*55}")

        # Clear previous findings
        for item in self.tree.get_children():
            self.tree.delete(item)

        thread = threading.Thread(target=self._scan_worker, daemon=True)
        thread.start()

    def _scan_worker(self):
        start = datetime.datetime.now()
        try:
            findings, risk, json_path, txt_path = run_scan(verbose=False)
            elapsed = (datetime.datetime.now() - start).total_seconds()
            self.root.after(0, self._update_ui, findings, risk, json_path, txt_path, elapsed)
        except Exception as e:
            self.root.after(0, self._scan_error, str(e))

    def _update_ui(self, findings, risk, json_path, txt_path, elapsed):
        self.progress.stop()
        self.scan_btn.config(state="normal")
        self.time_label.config(text=f"Scan time: {elapsed:.1f}s")

        # Update risk banner
        level_colors = {
            "CLEAN":       GREEN,
            "LOW RISK":    GREEN,
            "MEDIUM RISK": YELLOW,
            "HIGH RISK":   RED,
        }
        color = level_colors.get(risk["level"], FG)
        self.risk_label.config(text=f"🔍  {risk['level']}  —  {risk['description']}", fg=color)
        self.risk_frame.config(bg=BG3)

        # Update stat cards
        self.card_total.config(text=str(risk["total_findings"]))
        self.card_high.config(text=str(risk["high_count"]))
        self.card_medium.config(text=str(risk["medium_count"]))
        self.card_score.config(text=str(risk["score"]))

        # Populate findings tree
        for f in findings:
            sev = f.get("severity", "INFO")
            ftype = f.get("type", "Unknown")
            detail = (
                f.get("path") or f.get("cmdline") or
                f.get("message") or f.get("details") or
                f.get("entry_value") or "—"
            )[:80]
            ts = f.get("timestamp", "")[:19]
            self.tree.insert("", "end", values=(sev, ftype, detail, ts), tags=(sev,))

        # Log output
        self._log(f"\n  Risk Level : {risk['level']}  (Score: {risk['score']})")
        self._log(f"  Findings   : {risk['total_findings']} total | "
                  f"{risk['high_count']} HIGH | {risk['medium_count']} MEDIUM")
        self._log(f"\n  Report (JSON): {json_path}")
        self._log(f"  Report (TXT) : {txt_path}")
        self._log(f"\n  Scan completed in {elapsed:.1f} seconds.")

    def _scan_error(self, msg):
        self.progress.stop()
        self.scan_btn.config(state="normal")
        self._log(f"\n  ERROR: {msg}")
        messagebox.showerror("Scan Error", msg)

    def _log(self, text):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def _clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")
        self.risk_label.config(text="Run a scan to assess your system", fg=FG2)
        for card in (self.card_total, self.card_high, self.card_medium, self.card_score):
            card.config(text="—")
        self.time_label.config(text="")


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────
def main():
    root = tk.Tk()
    app = KeyShieldGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
