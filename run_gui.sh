#!/bin/bash
echo "[*] Launching backend server..."
source venv/bin/activate
cd backend
uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload