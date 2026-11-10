#!/usr/bin/env bash
# DRISHTI Cyber Intelligence Platform // Unix Launcher

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================================================================"
echo "          DRISHTI // SOVEREIGN CYBER DEFENSE PLATFORM (UNIX)"
echo "================================================================================"

if [ -f ".venv/bin/python" ]; then
    PYTHON_EXE=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_EXE="python3"
else
    echo "[ERROR] Python 3 was not found."
    exit 1
fi

echo "[*] Launching DRISHTI Unified Monolith on http://127.0.0.1:8000..."
"$PYTHON_EXE" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 &
SERVER_PID=$!

echo "[*] Server PID: $SERVER_PID. Waiting for ready signal..."
sleep 2

# Open browser depending on OS
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:8000"
elif command -v open >/dev/null 2>&1; then
    open "http://127.0.0.1:8000"
fi

wait $SERVER_PID
