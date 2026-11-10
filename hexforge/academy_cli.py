"""CLI de la academia hexadecimal."""
import argparse
import json
from .academy import hex_to_binary, binary_to_hex

def main():
    parser = argparse.ArgumentParser(description="NEXA Hex Academy")
    parser.add_argument("value")
    parser.add_argument("--from-base", choices=["hex", "bin"], default="hex")
    args = parser.parse_args()
    result = hex_to_binary(args.value) if args.from_base == "hex" else binary_to_hex(args.value)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
