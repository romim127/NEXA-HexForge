"""CLI educativa A6: explica la conversión de RVA a offset."""
import argparse
import json
from .rva_academy import inspect_rva

def main():
    parser = argparse.ArgumentParser(description="NEXA Hex Academy A6 — RVA Mapping")
    parser.add_argument("file")
    parser.add_argument("--rva", required=True, type=lambda s: int(s, 0))
    args = parser.parse_args()
    print(json.dumps(inspect_rva(args.file, args.rva), indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
