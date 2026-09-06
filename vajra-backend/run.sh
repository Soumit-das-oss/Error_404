#!/usr/bin/env bash
set -e

# Base directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "   Launching VAJRA Forensic Backend API   "
echo "=========================================="

# Locate virtual environment (.venv, venv) or system uvicorn
if [ -f ".venv/bin/uvicorn" ]; then
    UVICORN_EXEC=".venv/bin/uvicorn"
elif [ -f "venv/bin/uvicorn" ]; then
    UVICORN_EXEC="venv/bin/uvicorn"
elif [ -f ".venv/Scripts/uvicorn.exe" ]; then
    UVICORN_EXEC=".venv/Scripts/uvicorn.exe"
elif [ -f "venv/Scripts/uvicorn.exe" ]; then
    UVICORN_EXEC="venv/Scripts/uvicorn.exe"
elif command -v uvicorn &> /dev/null; then
    UVICORN_EXEC="uvicorn"
else
    echo "[!] Uvicorn not found in .venv, venv, or PATH."
    echo "[*] Please activate your Python virtual environment or install dependencies:"
    echo "    python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

echo "[*] Starting FastAPI Uvicorn server on http://0.0.0.0:8000 (reload enabled)..."
exec "$UVICORN_EXEC" app.main:app --host 0.0.0.0 --port 8000 --reload
