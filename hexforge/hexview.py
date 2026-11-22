"""Visor hexadecimal con offsets verificables y lectura acotada."""
from pathlib import Path
from .file_utils import secure_open_file

def hex_rows(path: str | Path, offset: int = 0, length: int = 256, width: int = 16) -> list[dict]:
    if type(offset) is not int or offset < 0:
        raise ValueError("Offset inválido.")
    if type(length) is not int or not 0 <= length <= 65536:
        raise ValueError("La lectura debe estar entre 0 y 65536 bytes.")
    if type(width) is not int or width not in (8, 16, 32):
        raise ValueError("Ancho permitido: 8, 16 o 32 bytes.")
    source = Path(path)
    stream = secure_open_file(source, purpose="hex view")
    with stream:
        stream.seek(offset)
        data = stream.read(length)
    return [
        {"offset_decimal": offset + i, "offset_hex": f"0x{offset+i:08X}",
         "hex": data[i:i+width].hex(" ").upper(),
         "ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in data[i:i+width])}
        for i in range(0, len(data), width)
    ]
