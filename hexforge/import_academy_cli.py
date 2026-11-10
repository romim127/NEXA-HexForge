"""A5: CLI de explicación de importaciones."""
import argparse
import json
from .import_academy import explain_imports

def main():
    parser = argparse.ArgumentParser(description="NEXA Hex Academy A5 — Import Intelligence")
    parser.add_argument("file")
    args = parser.parse_args()
    print(json.dumps(explain_imports(args.file), indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
