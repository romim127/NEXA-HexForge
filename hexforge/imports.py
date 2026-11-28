"""Lectura defensiva y acotada de importaciones PE, sin ejecutar el archivo."""
from pathlib import Path
from struct import unpack_from
from .pe import inspect_pe, PEError
from .file_utils import secure_open_file

MAX_IMPORT_DESCRIPTORS = 256
MAX_THUNKS_PER_DLL = 2048
MAX_NAME = 512

class ImportsError(ValueError):
    """Error durante el análisis de importaciones con código de estado."""
    def __init__(self, message: str, state: str = "error"):
        super().__init__(message)
        self.state = state

def inspect_imports(path: str | Path) -> dict:
    pe = inspect_pe(path)

    # Si el archivo no es PE válido, propagar el estado
    if pe.get("state") == "not_applicable":
        return {
            "state": "not_applicable",
            "reason": pe.get("reason", "El archivo no es un ejecutable PE válido."),
            "execution_performed": False,
        }
    if pe.get("state") == "error":
        raise ImportsError("Error en análisis PE previo.", state="error")

    p = Path(path)
    f = secure_open_file(p, purpose="import inspection")
    with f:
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
            return {
                "state": "completed",
                "imports": [],
                "reason": "PE válido sin directorio de importaciones.",
                "execution_performed": False,
            }
        import_rva, import_size = unpack_from("<II", opt, directory_base + 8)
        if not import_rva or not import_size:
            return {
                "state": "completed",
                "imports": [],
                "reason": "PE válido sin directorio de importaciones (RVA/size nulos).",
                "execution_performed": False,
            }

        def rva_offset(rva: int, length: int = 1) -> int:
            if length < 0: raise ImportsError("Longitud inválida.", state="error")
            for s in pe["sections"]:
                start = s["virtual_address"]
                raw_size = s["raw_size"]
                if start <= rva and rva - start + length <= raw_size:
                    off = s["raw_offset"] + rva - start
                    if off + length <= file_size: return off
            raise ImportsError(f"RVA 0x{rva:X} fuera de secciones respaldadas por archivo.", state="error")

        def read_rva(rva: int, length: int) -> bytes:
            f.seek(rva_offset(rva, length))
            data = f.read(length)
            if len(data) != length: raise ImportsError("Datos de importación truncados.", state="error")
            return data

        def read_name(rva: int) -> str:
            off = rva_offset(rva)
            f.seek(off)
            data = f.read(min(MAX_NAME, file_size - off))
            end = data.find(bytes([0]))
            if end < 0: raise ImportsError("Cadena de importación sin terminador dentro del límite.", state="error")
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
            if not name_rva: raise ImportsError("Descriptor sin DLL.", state="error")
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
            if not terminated_thunks: raise ImportsError("Límite de funciones importadas excedido.", state="error")
            imports.append({"dll": dll, "functions": functions})
        if not terminated: raise ImportsError("Directorio de importaciones sin terminador dentro del límite.", state="error")

        if not imports:
            return {
                "state": "completed",
                "imports": [],
                "reason": "PE válido con directorio de importaciones pero sin DLLs importadas.",
                "execution_performed": False,
                "limitations": ["No incluye delay-load imports, imports resueltos dinámicamente ni APIs observadas en ejecución.",
                                "La presencia de una API importada no demuestra que haya sido llamada."]
            }

        return {
            "state": "completed",
            "imports": imports,
            "execution_performed": False,
            "limitations": [
                "No incluye delay-load imports, imports resueltos dinámicamente ni APIs observadas en ejecución.",
                "La presencia de una API importada no demuestra que haya sido llamada."
            ]
        }
