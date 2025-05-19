#!/bin/bash
echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install fastapi uvicorn flask pyshark watchdog cryptography

echo "[*] To run the toolkit:"
echo "source venv/bin/activate && ./run_gui.sh"