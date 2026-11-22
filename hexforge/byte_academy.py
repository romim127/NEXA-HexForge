"""A2: explicación bit a bit de bytes de archivos; lectura de solo lectura."""
from pathlib import Path
from .file_utils import secure_open_file

WEIGHTS = (128, 64, 32, 16, 8, 4, 2, 1)

def explain_byte(value: int, offset: int = 0) -> dict:
    if type(value) is not int or not 0 <= value <= 255:
        raise ValueError("El byte debe estar entre 0 y 255.")
    if type(offset) is not int or offset < 0:
        raise ValueError("Offset inválido.")
    bits = f"{value:08b}"
    steps = [{"bit_index": i, "bit": int(bit), "weight": WEIGHTS[i],
              "contribution": int(bit) * WEIGHTS[i]} for i, bit in enumerate(bits)]
    return {"offset_decimal": offset, "offset_hex": f"0x{offset:08X}",
            "hex": f"{value:02X}", "binary": bits, "decimal": value,
            "ascii": chr(value) if 32 <= value <= 126 else ".",
            "printable_ascii": 32 <= value <= 126,
            "steps": steps,
            "formula": " + ".join(f"{s['bit']}×{s['weight']}" for s in steps),
            "limitations": ["ASCII se muestra solo para bytes imprimibles 0x20–0x7E.",
                            "Un byte aislado no determina codificación, tipo de archivo ni intención."]}

def inspect_byte(path: str | Path, offset: int = 0) -> dict:
    if type(offset) is not int or offset < 0:
        raise ValueError("Offset inválido.")
    p = Path(path)
    stream = secure_open_file(p, purpose="byte inspection")
    with stream:
        stream.seek(offset)
        value = stream.read(1)
    if not value:
        raise ValueError("Offset fuera del archivo o archivo vacío.")
    return explain_byte(value[0], offset)
