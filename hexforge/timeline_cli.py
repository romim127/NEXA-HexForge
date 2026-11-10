"""C2: CLI de línea de tiempo correlacionada."""
import argparse
import json
from .artifacts import load_export
from .core import write_report
from .timeline import correlate

def main():
    parser = argparse.ArgumentParser(description="NEXA HexForge C2: línea de tiempo de evidencia")
    parser.add_argument("csv", help="Exportación normalizada C1")
    parser.add_argument("--window", type=int, default=300, help="Ventana de asociación en segundos")
    parser.add_argument("--report", help="Guardar JSON sin sobrescribir")
    args = parser.parse_args()
    report = correlate(load_export(args.csv), args.window)
    if args.report: write_report(report, args.report)
    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
