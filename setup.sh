#!/bin/bash
# NetRunner OS - Setup Script
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║     NetRunner OS - Setup Script      ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# Check Python 3
echo -n "[*] Checking Python 3... "
if command -v python3 &> /dev/null; then
    PY_VERSION=$(python3 --version 2>&1)
    echo -e "${GREEN}${PY_VERSION}${NC}"
else
    echo -e "${RED}NOT FOUND${NC}"
    echo "    Please install Python 3.8+ and try again."
    exit 1
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt --quiet

# Validate imports
echo -n "[*] Validating Flask... "
if python3 -c "import flask" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    exit 1
fi

echo -n "[*] Validating Scapy... "
if python3 -c "import scapy" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "    You may need to install libpcap: brew install libpcap (Mac) or apt install libpcap-dev (Linux)"
    exit 1
fi

# Create required directories
echo "[*] Creating directories..."
mkdir -p data/profiles uploads

echo ""
echo -e "${GREEN}[+] Setup complete!${NC}"
echo ""
echo "    To start NetRunner OS:"
echo "      source venv/bin/activate"
echo "      sudo python3 run.py"
echo ""
echo "    Then open: http://127.0.0.1:9000"
echo ""
