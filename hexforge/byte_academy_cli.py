"""CLI A2: explica un byte de un archivo sin ejecutarlo."""
import argparse
import json
from .byte_academy import inspect_byte

def main():
    parser = argparse.ArgumentParser(description="NEXA Hex Academy A2 — Byte Inspector")
    parser.add_argument("file")
    parser.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    args = parser.parse_args()
    print(json.dumps(inspect_byte(args.file, args.offset), indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
