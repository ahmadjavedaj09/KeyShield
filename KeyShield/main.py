#!/usr/bin/env python3
"""
KeyShield — Keylogger Detection & Defense Tool
Entry point: supports CLI and GUI modes.

Usage:
    python main.py          # Launch GUI
    python main.py --cli    # Run CLI scan only
    python main.py --help   # Show help
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="KeyShield — Keylogger Detection & Defense Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py            Launch the GUI dashboard
  python main.py --cli      Run a CLI scan and save reports
  python main.py --cli --output ./my_reports
        """
    )
    parser.add_argument(
        "--cli", action="store_true",
        help="Run in command-line mode (no GUI)"
    )
    parser.add_argument(
        "--output", default="reports",
        help="Directory to save reports (default: reports/)"
    )
    args = parser.parse_args()

    if args.cli:
        from src.detector import run_scan
        run_scan(verbose=True)
    else:
        try:
            import tkinter as tk
            from src.gui import main as gui_main
            gui_main()
        except ImportError:
            print("[!] Tkinter not available. Falling back to CLI mode.")
            from src.detector import run_scan
            run_scan(verbose=True)


if __name__ == "__main__":
    main()
