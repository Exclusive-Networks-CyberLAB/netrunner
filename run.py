#!/usr/bin/env python3
"""
NetRunner OS - Entry Point
Start with: sudo python3 run.py
"""

import sys
import os

# Dependency check
try:
    import flask
    import scapy
except ImportError as e:
    print(f"\n[!] Missing dependency: {e}")
    print("    Run:  pip install -r requirements.txt")
    print("    Or:   bash setup.sh\n")
    sys.exit(1)

from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 9000))
    print(f"\n[*] NetRunner OS starting on http://127.0.0.1:{port}")
    print(f"[*] Running as: {os.getenv('USER', 'unknown')}")
    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. Replay/generation requires sudo.\n")
    app.run(host='0.0.0.0', port=port, debug=True)
