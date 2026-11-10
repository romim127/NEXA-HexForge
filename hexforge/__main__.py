"""CLI de inspección forense estática."""
import argparse
import json
from .core import inspect_file, write_report
from .hexview import hex_rows
from .pe import inspect_pe
from .strings import extract_strings
from .indicators import section_indicators
from .imports import inspect_imports

def main():
    parser = argparse.ArgumentParser(description="NEXA HexForge: inspección binaria sin ejecución")
    parser.add_argument("file", help="Ruta de la muestra o archivo de evidencia")
    parser.add_argument("--preview", type=int, default=256, help="Bytes a visualizar (0–4096)")
    parser.add_argument("--report", help="Guardar reporte JSON en archivo nuevo")
    parser.add_argument("--hex-offset", type=lambda s: int(s, 0), help="Offset para lectura HEX (decimal o 0x...)")
    parser.add_argument("--hex-length", type=int, default=256, help="Máximo 65536 bytes")
    parser.add_argument("--pe", action="store_true", help="Inspeccionar estructura PE")
    parser.add_argument("--strings", action="store_true", help="Extraer strings ASCII y UTF-16LE")
    parser.add_argument("--strings-limit", type=int, default=200, help="Máximo de strings")
    parser.add_argument("--indicators", action="store_true", help="Indicadores de secciones PE")
    parser.add_argument("--imports", action="store_true", help="Importaciones PE")
    args = parser.parse_args()
    result = inspect_file(args.file, args.preview)
    if args.hex_offset is not None:
        result["hex_rows"] = hex_rows(args.file, args.hex_offset, args.hex_length)
    if args.pe:
        result["pe_structure"] = inspect_pe(args.file)
    if args.strings:
        result["strings"] = extract_strings(args.file, max_results=args.strings_limit)
    if args.indicators:
        result["section_indicators"] = section_indicators(args.file)
    if args.imports:
        result["pe_imports"] = inspect_imports(args.file)
    if args.report: write_report(result, args.report)
    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
