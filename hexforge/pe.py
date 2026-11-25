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

def _u64(buf, offset):
    if offset < 0 or offset + 8 > len(buf): raise ValueError("Campo PE truncado.")
    return unpack_from("<Q", buf, offset)[0]

class PEError(ValueError):
    """Error durante el análisis PE con código de estado."""
    def __init__(self, message: str, state: str = "error"):
        super().__init__(message)
        self.state = state


def _read_coff_string_table(f, pe_offset: int, optional_size: int, sections_count: int, file_size: int) -> bytes:
    """
    Lee la tabla de cadenas COFF si existe.
    La tabla de símbolos COFF está en: COFF header + optional header + section table
    Pero el offset real está en el COFF header (PointerToSymbolTable).
    """
    # COFF header starts at pe_offset + 4 (after PE signature)
    # COFF header is 20 bytes: Machine(2) + NumberOfSections(2) + TimeDateStamp(4) +
    #                          PointerToSymbolTable(4) + NumberOfSymbols(4) + SizeOfOptionalHeader(2) + Characteristics(2)
    coff_header_offset = pe_offset + 4
    if coff_header_offset + 20 > file_size:
        return b""

    f.seek(coff_header_offset)
    coff_header = f.read(20)
    if len(coff_header) < 20:
        return b""

    # PointerToSymbolTable is at offset 8 in COFF header (after Machine[2] + NumberOfSections[2] + TimeDateStamp[4])
    ptr_to_symbol_table = _u32(coff_header, 8)
    number_of_symbols = _u32(coff_header, 12)

    # Validate symbol table pointer
    if ptr_to_symbol_table == 0 or number_of_symbols == 0:
        return b""

    # Each symbol entry is 18 bytes
    symbol_table_size = number_of_symbols * 18
    string_table_offset = ptr_to_symbol_table + symbol_table_size

    # Validate string table offset and size
    if string_table_offset >= file_size:
        return b""

    # String table starts with 4-byte length (including those 4 bytes)
    f.seek(string_table_offset)
    str_table_len_bytes = f.read(4)
    if len(str_table_len_bytes) < 4:
        return b""

    str_table_len = _u32(str_table_len_bytes, 0)
    if str_table_len < 4 or string_table_offset + str_table_len > file_size:
        return b""

    # Read the string table (including the 4-byte length prefix)
    f.seek(string_table_offset)
    string_table = f.read(str_table_len)
    if len(string_table) != str_table_len:
        return b""

    return string_table


def _resolve_section_name(name_field: bytes, string_table: bytes) -> tuple[str, str]:
    """
    Resuelve el nombre de sección.
    Retorna (original_name, resolved_name).
    - Si name_field empieza con '/', es una referencia a la string table.
    - Si name_field es <= 8 bytes y null-terminated, es el nombre directo.
    """
    # Decode the 8-byte name field
    raw_name = name_field.split(b"\x00", 1)[0]
    original = raw_name.decode("ascii", "replace")

    # Check for string table reference: "/<offset>"
    if raw_name.startswith(b"/"):
        try:
            offset_str = raw_name[1:].decode("ascii")
            if offset_str.isdigit():
                offset = int(offset_str)
                # String table has 4-byte length prefix, so actual strings start at offset 4
                if offset >= 4 and offset < len(string_table):
                    # Read null-terminated string from string table
                    end = string_table.find(b"\x00", offset)
                    if end != -1:
                        resolved = string_table[offset:end].decode("ascii", "replace")
                        return original, resolved
        except (ValueError, UnicodeDecodeError):
            pass

    return original, original

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

        # Read COFF string table for long section names
        string_table = _read_coff_string_table(f, pe_offset, optional_size, sections_count, size)

        f.seek(table_offset)
        table = f.read(table_size)
        sections = []
        for i in range(sections_count):
            pos = i * 40
            raw = table[pos:pos+40]
            name_field = raw[:8]
            original_name, resolved_name = _resolve_section_name(name_field, string_table)
            virtual_size = _u32(raw, 8)
            virtual_address = _u32(raw, 12)
            raw_size = _u32(raw, 16)
            raw_offset = _u32(raw, 20)
            flags = _u32(raw, 36)
            if raw_size and (raw_offset == 0 or raw_offset + raw_size > size):
                raise PEError(f"Sección {i} apunta fuera del archivo.", state="error")
            section_data = {
                "name": resolved_name,
                "virtual_size": virtual_size, "virtual_address": virtual_address,
                "raw_size": raw_size, "raw_offset": raw_offset, "characteristics": f"0x{flags:08X}",
                "executable": bool(flags & 0x20000000), "writable": bool(flags & 0x80000000)
            }
            # Preserve original name for forensic traceability
            if original_name != resolved_name:
                section_data["name_original"] = original_name
            sections.append(section_data)
    limitations = [
        "Structural parsing does not establish benign or malicious behavior.",
        "Imports, resources, certificates, relocations and overlay are not yet parsed.",
        "Passing structural checks does not guarantee a loadable executable."
    ]
    if string_table:
        limitations.append("Long section names resolved from COFF string table; original names preserved in name_original.")
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
        "limitations": limitations
    }
