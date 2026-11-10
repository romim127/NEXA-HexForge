"""Lectura defensiva y acotada de importaciones PE, sin ejecutar el archivo."""
from pathlib import Path
from struct import unpack_from
from .pe import inspect_pe

MAX_IMPORT_DESCRIPTORS = 256
MAX_THUNKS_PER_DLL = 2048
MAX_NAME = 512

def inspect_imports(path: str | Path) -> dict:
    pe = inspect_pe(path)
    p = Path(path)
    with p.open("rb") as f:
        f.seek(0, 2)
        file_size = f.tell()
        f.seek(0x3C)
        pe_offset = unpack_from("<I", f.read(4))[0]
        f.seek(pe_offset + 20)
        opt_size = unpack_from("<H", f.read(2))[0]
        f.seek(pe_offset + 24)
        opt = f.read(opt_size)
        pe64 = pe["format"] == "PE32+"
        directory_base = 112 if pe64 else 96
        number_of_rva_offset = 108 if pe64 else 92
        count = unpack_from("<I", opt, number_of_rva_offset)[0]
        if count < 2:
            return {"imports": [], "status": "no_import_directory", "execution_performed": False}
        import_rva, import_size = unpack_from("<II", opt, directory_base + 8)
        if not import_rva or not import_size:
            return {"imports": [], "status": "no_import_directory", "execution_performed": False}

        def rva_offset(rva: int, length: int = 1) -> int:
            if length < 0: raise ValueError("Longitud inválida.")
            for s in pe["sections"]:
                start = s["virtual_address"]
                raw_size = s["raw_size"]
                if start <= rva and rva - start + length <= raw_size:
                    off = s["raw_offset"] + rva - start
                    if off + length <= file_size: return off
            raise ValueError(f"RVA 0x{rva:X} fuera de secciones respaldadas por archivo.")

        def read_rva(rva: int, length: int) -> bytes:
            f.seek(rva_offset(rva, length))
            data = f.read(length)
            if len(data) != length: raise ValueError("Datos de importación truncados.")
            return data

        def read_name(rva: int) -> str:
            off = rva_offset(rva)
            f.seek(off)
            data = f.read(min(MAX_NAME, file_size - off))
            end = data.find(bytes([0]))
            if end < 0: raise ValueError("Cadena de importación sin terminador dentro del límite.")
            return data[:end].decode("ascii", "replace")

        imports = []
        max_descriptors = min(MAX_IMPORT_DESCRIPTORS, import_size // 20)
        terminated = False
        for i in range(max_descriptors):
            descriptor = read_rva(import_rva + i * 20, 20)
            original, timestamp, forwarder, name_rva, first = unpack_from("<IIIII", descriptor)
            if not any((original, timestamp, forwarder, name_rva, first)):
                terminated = True
                break
            if not name_rva: raise ValueError("Descriptor sin DLL.")
            dll = read_name(name_rva)
            thunk_rva = original or first
            functions = []
            width = 8 if pe64 else 4
            ordinal_mask = 1 << (63 if pe64 else 31)
            terminated_thunks = False
            for j in range(MAX_THUNKS_PER_DLL):
                value = unpack_from("<Q" if pe64 else "<I", read_rva(thunk_rva + j * width, width))[0]
                if value == 0:
                    terminated_thunks = True
                    break
                if value & ordinal_mask:
                    functions.append({"ordinal": value & 0xFFFF})
                else:
                    name = read_name(value + 2)
                    functions.append({"name": name})
            if not terminated_thunks: raise ValueError("Límite de funciones importadas excedido.")
            imports.append({"dll": dll, "functions": functions})
        if not terminated: raise ValueError("Directorio de importaciones sin terminador dentro del límite.")
        return {"imports": imports, "status": "parsed", "execution_performed": False,
                "limitations": ["No incluye delay-load imports, imports resueltos dinámicamente ni APIs observadas en ejecución.",
                                "La presencia de una API importada no demuestra que haya sido llamada."]}
