"""CLI de inspección forense estática."""
import argparse
import json
from .core import inspect_file, write_report

def main():
    parser = argparse.ArgumentParser(description="NEXA HexForge: inspección binaria sin ejecución")
    parser.add_argument("file", help="Ruta de la muestra o archivo de evidencia")
    parser.add_argument("--preview", type=int, default=256, help="Bytes a visualizar (0–4096)")
    parser.add_argument("--report", help="Guardar reporte JSON en archivo nuevo")
    args = parser.parse_args()
    result = inspect_file(args.file, args.preview)
    if args.report: write_report(result, args.report)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
