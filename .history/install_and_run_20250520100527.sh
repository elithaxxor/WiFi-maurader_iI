#!/usr/bin/env bash
# ==========================================================
# WiFi Marauder – Automated Install & Run Script
# ----------------------------------------------------------
# This script bootstraps the Python virtual environment,   
# installs Python package dependencies and OS-level tools, 
# and finally launches the WiFi Marauder application.      
# ==========================================================
set -e  # Exit immediately if a command exits with non-zero status

# ---------- Helper Functions ----------
print_section() {
  echo -e "\n\033[1;34m[*]\033[0m $1\n"  # Bold blue prefix
}

# ---------- Detect Project Root ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------- Python & Virtual Environment ----------
print_section "Setting up Python virtual environment…"
if ! command -v python3 &>/dev/null; then
  echo "❌ Python 3 is required but not found in PATH." >&2
  exit 1
fi

if [ ! -d "venv" ]; then
  python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate

print_section "Upgrading pip…"
pip install --quiet --upgrade pip

# ---------- Python Dependencies ----------
print_section "Installing Python dependencies…"

# Install core requirements
if [ -f requirements.txt ]; then
  pip install --quiet -r requirements.txt
fi

# Extra libraries used by the toolkit
pip install --quiet qdarktheme pyshark watchdog cryptography fastapi uvicorn flask

# ---------- OS-Level Tooling ----------
print_section "Installing external Wi-Fi & Bluetooth tooling (optional)…"
# These installations are best-effort. Failures won’t stop the app.
python install_tools.py || echo "⚠️  install_tools.py encountered errors or some tools need manual install. Continuing…"

# ---------- Launch Application ----------
print_section "Launching WiFi Marauder GUI…"
python main.py
