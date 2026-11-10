"""Offline Registry Monitor CLI for normalized Sysmon JSON exports."""
import argparse
import json
from .registry_monitor import analyze_export

def main():
    parser = argparse.ArgumentParser(description="NEXA Registry Monitor — análisis offline de Sysmon")
    parser.add_argument("export_json", help="Lista JSON normalizada de eventos Sysmon 12/13/14")
    args = parser.parse_args()
    print(json.dumps(analyze_export(args.export_json), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
