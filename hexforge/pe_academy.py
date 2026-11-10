"""Academy A3: explica campos PE observados, sin ejecutar el archivo."""
from pathlib import Path
from .pe import inspect_pe

MACHINES = {"0x014C": "Intel x86", "0x8664": "AMD64 / x86-64", "0xAA64": "ARM64"}

def explain_pe(path: str | Path) -> dict:
    pe = inspect_pe(path)
    offset = pe["pe_header_offset"]
    fields = [
        {"field": "e_magic", "offset_hex": "0x00000000", "value": "4D 5A",
         "meaning": "Firma DOS MZ: identifica un encabezado compatible; no prueba que sea ejecutable válido."},
        {"field": "e_lfanew", "offset_hex": "0x0000003C", "value": f"0x{offset:X}",
         "meaning": "Entero little-endian de 32 bits que apunta al encabezado PE."},
        {"field": "PE signature", "offset_hex": f"0x{offset:08X}", "value": "50 45 00 00",
         "meaning": "Firma PE seguida de dos bytes nulos; no acredita legitimidad."},
        {"field": "Machine", "offset_hex": f"0x{offset+4:08X}", "value": pe["machine"],
         "meaning": MACHINES.get(pe["machine"], "Arquitectura declarada no identificada en este catálogo.")},
        {"field": "NumberOfSections", "offset_hex": f"0x{offset+6:08X}",
         "value": str(pe["section_count"]), "meaning": "Cantidad declarada de entradas en la tabla de secciones."},
        {"field": "AddressOfEntryPoint", "offset_hex": f"0x{offset+24+16:08X}",
         "value": f"0x{pe['entry_point_rva']:X}",
         "meaning": "Dirección virtual relativa (RVA) declarada; no es offset físico ni evidencia de ejecución."},
        {"field": "ImageBase", "offset_hex": f"0x{offset+24+(28 if pe['format']=='PE32' else 24):08X}",
         "value": pe["image_base"], "meaning": "Dirección base preferida de carga; puede cambiar por ASLR."}
    ]
    sections = [
        {"name": s["name"], "rva": f"0x{s['virtual_address']:X}",
         "file_offset": f"0x{s['raw_offset']:X}", "raw_size": s["raw_size"],
         "executable": s["executable"], "writable": s["writable"],
         "meaning": "Características declaradas; no son prueba de que se ejecutó código."}
        for s in pe["sections"]
    ]
    return {"module": "Academy A3", "format": pe["format"], "fields": fields,
            "sections": sections, "execution_performed": False,
            "limitations": ["El análisis es estático y estructural.",
                            "RVA y offset de archivo son conceptos diferentes.",
                            "El punto de entrada declarado no demuestra ejecución.",
                            "El parser PE actual es parcial y no garantiza que el sistema operativo pueda cargar el archivo."]}
