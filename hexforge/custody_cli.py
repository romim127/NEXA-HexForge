"""C3: registro inicial y verificación de evidencia sin sobrescritura."""
import argparse
import json
from .custody import register_evidence, save_new, load_record, verify_evidence

def main():
    parser = argparse.ArgumentParser(description="NEXA HexForge C3: custodia e integridad")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("register")
    add.add_argument("file")
    add.add_argument("--id", required=True)
    add.add_argument("--actor", required=True)
    add.add_argument("--report", required=True)
    check = sub.add_parser("verify")
    check.add_argument("record")
    check.add_argument("file")
    args = parser.parse_args()
    if args.command == "register":
        result = register_evidence(args.id, args.file, args.actor)
        save_new(result, args.report)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(verify_evidence(load_record(args.record), args.file), indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
