"""Parser PE mínimo defensivo, sin carga ni ejecución del binario."""
from pathlib import Path
from struct import unpack_from
from .file_utils import secure_open_file

MAX_SECTIONS = 96
MAX_HEADER = 1024 * 1024

def _u16(buf, offset):
    if offset < 0 or offset + 2 > len(buf): raise ValueError("Campo PE truncado.")
    return unpack_from("<H", buf, offset)[0]

def _u32(buf, offset):
    if offset < 0 or offset + 4 > len(buf): raise ValueError("Campo PE truncado.")
    return unpack_from("<I", buf, offset)[0]

class PEError(ValueError):
    """Error durante el análisis PE con código de estado."""
    def __init__(self, message: str, state: str = "error"):
        super().__init__(message)
        self.state = state

def inspect_pe(path: str | Path) -> dict:
    source = Path(path)
    f = secure_open_file(source, purpose="PE inspection")
    with f:
        f.seek(0, 2)
        size = f.tell()
        if size < 64:
            return {
                "state": "not_applicable",
                "reason": "Archivo demasiado pequeño para contener una cabecera DOS válida (mínimo 64 bytes).",
                "execution_performed": False,
                "format": None,
            }
        f.seek(0)
        dos = f.read(64)
        if dos[:2] != b"MZ":
            return {
                "state": "not_applicable",
                "reason": "El archivo no contiene firma DOS MZ. No es un ejecutable PE válido.",
                "execution_performed": False,
                "format": None,
            }
        pe_offset = _u32(dos, 0x3C)
        if pe_offset < 64 or pe_offset > MAX_HEADER - 24 or pe_offset + 24 > size:
            raise PEError("e_lfanew fuera de límites.", state="error")
        f.seek(pe_offset)
        head = f.read(24)
        if head[:4] != b"PE\x00\x00":
            return {
                "state": "not_applicable",
                "reason": "Firma PE inválida. El archivo tiene MZ pero no la estructura PE completa.",
                "execution_performed": False,
                "format": None,
            }
        machine = _u16(head, 4)
        sections_count = _u16(head, 6)
        optional_size = _u16(head, 20)
        characteristics = _u16(head, 22)
        if sections_count > MAX_SECTIONS:
            raise PEError("Demasiadas secciones PE.", state="error")
        table_offset = pe_offset + 24 + optional_size
        table_size = sections_count * 40
        if table_offset + table_size > size or table_offset + table_size > MAX_HEADER:
            raise PEError("Tabla de secciones truncada o demasiado grande.", state="error")
        f.seek(pe_offset + 24)
        optional = f.read(optional_size)
        if len(optional) != optional_size:
            raise PEError("Optional header truncado.", state="error")
        magic = _u16(optional, 0) if optional_size >= 2 else None
        if magic not in (0x10B, 0x20B):
            return {
                "state": "not_applicable",
                "reason": "Optional header PE32/PE32+ inválido.",
                "execution_performed": False,
                "format": None,
            }
        min_optional = 96 if magic == 0x10B else 112
        if optional_size < min_optional:
            raise PEError("Optional header PE truncado.", state="error")
        entry_rva = _u32(optional, 16)
        image_base = _u32(optional, 28) if magic == 0x10B else unpack_from("<Q", optional, 24)[0]
        f.seek(table_offset)
        table = f.read(table_size)
        sections = []
        for i in range(sections_count):
            pos = i * 40
            raw = table[pos:pos+40]
            name = raw[:8].split(b"\x00", 1)[0].decode("ascii", "replace")
            virtual_size = _u32(raw, 8)
            virtual_address = _u32(raw, 12)
            raw_size = _u32(raw, 16)
            raw_offset = _u32(raw, 20)
            flags = _u32(raw, 36)
            if raw_size and (raw_offset == 0 or raw_offset + raw_size > size):
                raise PEError(f"Sección {i} apunta fuera del archivo.", state="error")
            sections.append({
                "name": name, "virtual_size": virtual_size, "virtual_address": virtual_address,
                "raw_size": raw_size, "raw_offset": raw_offset, "characteristics": f"0x{flags:08X}",
                "executable": bool(flags & 0x20000000), "writable": bool(flags & 0x80000000)
            })
    return {
        "state": "completed",
        "format": "PE32" if magic == 0x10B else "PE32+",
        "machine": f"0x{machine:04X}",
        "characteristics": f"0x{characteristics:04X}",
        "pe_header_offset": pe_offset,
        "entry_point_rva": entry_rva,
        "image_base": f"0x{image_base:X}",
        "sections": sections,
        "section_count": sections_count,
        "execution_performed": False,
        "limitations": [
            "Structural parsing does not establish benign or malicious behavior.",
            "Imports, resources, certificates, relocations and overlay are not yet parsed.",
            "Passing structural checks does not guarantee a loadable executable."
        ]
    }
