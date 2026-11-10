"""CLI para correlación de exportaciones CSV previamente normalizadas."""
import argparse
import json
from .artifacts import load_export, timeline
from .core import write_report

def main():
    parser = argparse.ArgumentParser(description="NEXA HexForge C1: Prefetch/Amcache export correlator")
    parser.add_argument("csv", help="CSV normalizado UTF-8, sin muestras ejecutables")
    parser.add_argument("--report", help="Ruta de reporte JSON nuevo (sin sobrescritura)")
    args = parser.parse_args()
    export = load_export(args.csv)
    report = {"export": {k:v for k,v in export.items() if k != "records"}, "timeline": timeline(export)}
    if args.report:
        write_report(report, args.report)
    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
