#!/usr/bin/env bash
# NEXA-HexForge Local Console - Linux Launcher
# Starts the FastAPI server and opens the web interface

set -euo pipefail

# Configuration
DEFAULT_PORT=8765
DEFAULT_HOST="127.0.0.1"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_ROOT}/.venv"
PYTHON="${VENV_DIR}/bin/python"
UVICORN="${VENV_DIR}/bin/uvicorn"
SERVER_MODULE="hexforge.server.main:app"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    NEXA-HexForge Local Console                ║"
    echo "║              Binary Intelligence · Forensic Analysis         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if virtual environment exists
check_venv() {
    if [[ ! -f "${PYTHON}" ]]; then
        echo -e "${YELLOW}Virtual environment not found. Creating...${NC}"
        python3 -m venv "${VENV_DIR}"
        "${PYTHON}" -m pip install --upgrade pip
        "${PYTHON}" -m pip install -e "${PROJECT_ROOT}"
        "${PYTHON}" -m pip install fastapi uvicorn[standard] python-multipart
    fi
}

# Check if port is available
check_port() {
    local port=$1
    if command -v ss &> /dev/null; then
        ss -ltn | grep -q ":${port} " && return 1
    elif command -v netstat &> /dev/null; then
        netstat -ltn | grep -q ":${port} " && return 1
    else
        # Fallback using bash
        (echo > /dev/tcp/127.0.0.1/${port}) &>/dev/null && return 1
    fi
    return 0
}

# Find available port
find_port() {
    local port=$1
    while ! check_port ${port}; do
        echo -e "${YELLOW}Port ${port} in use, trying ${port}...${NC}"
        port=$((port + 1))
    done
    echo ${port}
}

# Main
main() {
    print_banner

    # Default values
    PORT=${DEFAULT_PORT}
    HOST=${DEFAULT_HOST}
    OPEN_BROWSER=true

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port=*)
                PORT="${1#*=}"
                shift
                ;;
            --host=*)
                HOST="${1#*=}"
                shift
                ;;
            --no-browser)
                OPEN_BROWSER=false
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --port=PORT       Server port (default: ${DEFAULT_PORT})"
                echo "  --host=HOST       Server host (default: ${DEFAULT_HOST})"
                echo "  --no-browser      Don't open browser automatically"
                echo "  --help, -h        Show this help"
                exit 0
                ;;
            *)
                # If it's a number, treat as port (backward compatibility)
                if [[ "$1" =~ ^[0-9]+$ ]]; then
                    PORT="$1"
                    shift
                else
                    echo -e "${RED}Unknown option: $1${NC}"
                    exit 1
                fi
                ;;
        esac
    done

    if [[ "${HOST}" != "127.0.0.1" && "${HOST}" != "localhost" ]]; then
        echo "Only loopback hosts are supported"; exit 1
    fi
    # Check virtual environment
    check_venv

    # Find available port
    PORT=$(find_port ${PORT})

    echo -e "${GREEN}Starting server on ${HOST}:${PORT}${NC}"
    echo -e "${BLUE}Project root: ${PROJECT_ROOT}${NC}"
    echo ""

    # Change to project root
    cd "${PROJECT_ROOT}"

    # Start server
    if [[ "${OPEN_BROWSER}" == "true" ]]; then
        # Open browser after a short delay
        (sleep 2 && xdg-open "http://${HOST}:${PORT}" 2>/dev/null || \
         open "http://${HOST}:${PORT}" 2>/dev/null || \
         sensible-browser "http://${HOST}:${PORT}" 2>/dev/null) &
    fi

    # Run uvicorn
    exec "${UVICORN}" ${SERVER_MODULE} \
        --host "${HOST}" \
        --port "${PORT}" \
        --log-level warning \
        --no-access-log
}

# Trap signals for clean shutdown
trap 'echo -e "\n${YELLOW}Shutting down...${NC}"; exit 0' INT TERM

main "$@"