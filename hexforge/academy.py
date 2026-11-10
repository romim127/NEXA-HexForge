"""NEXA Hex Academy: conversiones explicadas y acotadas, sin I/O."""
import re

MAX_DIGITS = 16

def hex_to_binary(value: str) -> dict:
    if not isinstance(value, str): raise ValueError("Se requiere texto hexadecimal.")
    cleaned = value.strip().upper()
    if cleaned.startswith("0X"): cleaned = cleaned[2:]
    cleaned = cleaned.replace(" ", "")
    if not 1 <= len(cleaned) <= MAX_DIGITS or not re.fullmatch("[0-9A-F]+", cleaned):
        raise ValueError("Ingrese entre 1 y 16 dígitos hexadecimales (0–9, A–F).")
    steps = []
    for position, digit in enumerate(cleaned):
        decimal = int(digit, 16)
        bits = f"{decimal:04b}"
        power = len(cleaned) - 1 - position
        steps.append({"position": position + 1, "hex_digit": digit,
                      "digit_decimal": decimal, "binary_nibble": bits,
                      "weight": 16 ** power, "contribution": decimal * (16 ** power),
                      "binary_explanation": " + ".join(
                          f"{bit}×{2**(3-i)}" for i, bit in enumerate(bits))})
    return {"input_hex": cleaned, "binary": "".join(s["binary_nibble"] for s in steps),
            "decimal": sum(s["contribution"] for s in steps), "steps": steps,
            "explanation": "Cada dígito hexadecimal equivale a 4 bits; en decimal se suma dígito × 16^posición."}

def binary_to_hex(value: str) -> dict:
    if not isinstance(value, str): raise ValueError("Se requiere texto binario.")
    bits = value.strip().replace(" ", "")
    if not 1 <= len(bits) <= MAX_DIGITS * 4 or not re.fullmatch("[01]+", bits):
        raise ValueError("Ingrese entre 1 y 64 bits.")
    padded = bits.zfill((len(bits) + 3) // 4 * 4)
    groups = [padded[i:i+4] for i in range(0, len(padded), 4)]
    return {"input_binary": bits, "padded_binary": padded,
            "hex": "".join(f"{int(g,2):X}" for g in groups),
            "steps": [{"binary_nibble":g, "decimal":int(g,2), "hex_digit":f"{int(g,2):X}"} for g in groups],
            "explanation": "Agrupar de derecha a izquierda en bloques de 4 bits; agregar ceros a la izquierda si hace falta."}
