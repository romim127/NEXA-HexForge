#!/usr/bin/env python3
"""CLI entry point for NEXA-HexForge Local Console Server."""
from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from hexforge.server.main import run_server, stop_server


def main():
    parser = argparse.ArgumentParser(
        description="NEXA-HexForge Local Console Server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (use 127.0.0.1 for localhost only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port to listen on",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't open browser automatically",
    )
    args = parser.parse_args()

    print(f"Starting NEXA-HexForge Local Console on {args.host}:{args.port}")
    print("Press Ctrl+C to stop")

    try:
        server = run_server(
            host=args.host,
            port=args.port,
            open_browser=not args.no_browser,
        )
        # Keep main thread alive
        import threading
        server_thread = threading.current_thread()
        # Wait for shutdown event
        from hexforge.server.main import _shutdown_event
        _shutdown_event.wait()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        stop_server()


if __name__ == "__main__":
    main()