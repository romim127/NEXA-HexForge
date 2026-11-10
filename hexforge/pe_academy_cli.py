"""CLI educativa PE."""
import argparse
import json
from .pe_academy import explain_pe

def main():
    parser = argparse.ArgumentParser(description="NEXA Hex Academy A3 — PE Header Explorer")
    parser.add_argument("file")
    args = parser.parse_args()
    print(json.dumps(explain_pe(args.file), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
