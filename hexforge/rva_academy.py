"""Academy A6: traducción didáctica RVA↔offset en secciones PE respaldadas por disco."""
from pathlib import Path
from .pe import inspect_pe

def _number(value):
    if type(value) is not int or value < 0 or value > 0xFFFFFFFF:
        raise ValueError("RVA/offset debe ser entero de 0 a 0xFFFFFFFF.")
    return value

def explain_rva(sections: list, rva: int, file_size: int | None = None) -> dict:
    _number(rva)
    if not isinstance(sections, list): raise ValueError("Secciones inválidas.")
    matches = []
    virtual_only = []
    for section in sections:
        start = section["virtual_address"]
        raw_size = section["raw_size"]
        virtual_size = section["virtual_size"]
        raw_offset = section["raw_offset"]
        if any(type(n) is not int or n < 0 for n in (start, raw_size, virtual_size, raw_offset)):
            raise ValueError("Metadatos de sección inválidos.")
        delta = rva - start
        if delta < 0: continue
        if delta < raw_size:
            physical = raw_offset + delta
            if file_size is not None and physical >= file_size: continue
            matches.append({"section": section["name"], "rva": f"0x{rva:X}",
                            "section_rva": f"0x{start:X}", "delta": f"0x{delta:X}",
                            "pointer_to_raw_data": f"0x{raw_offset:X}",
                            "file_offset": f"0x{physical:X}", "file_offset_decimal": physical,
                            "formula": f"0x{raw_offset:X} + (0x{rva:X} - 0x{start:X}) = 0x{physical:X}"})
        elif delta < virtual_size:
            virtual_only.append(section["name"])
    if len(matches) > 1:
        return {"status": "ambiguous_overlap", "candidates": matches,
                "warning": "Secciones con rangos RVA solapados; no elegir arbitrariamente."}
    if matches:
        return {"status": "mapped", **matches[0], "execution_performed": False,
                "note": "Esta traducción describe bytes respaldados por el archivo, no el estado real en memoria."}
    if virtual_only:
        return {"status": "virtual_only", "sections": virtual_only, "execution_performed": False,
                "note": "RVA en zona virtual sin bytes raw correspondientes; puede ser memoria inicializada en cero."}
    return {"status": "unmapped", "execution_performed": False,
            "note": "RVA fuera de secciones raw; podría corresponder a encabezados u otra región no modelada."}

def inspect_rva(path: str | Path, rva: int) -> dict:
    p = Path(path)
    pe = inspect_pe(p)
    result = explain_rva(pe["sections"], rva, p.stat().st_size)
    return {"module": "Academy A6", "format": pe["format"], "rva": f"0x{rva:X}",
            "image_base": pe["image_base"], "result": result,
            "limitations": ["Los encabezados y RVA no respaldados por secciones no se mapean en este prototipo.",
                            "La alineación en disco y memoria puede ser distinta.",
                            "ASLR y relocalizaciones pueden cambiar la dirección virtual efectiva.",
                            "No se infiere ejecución ni comportamiento."]}
