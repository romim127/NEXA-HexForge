"""Extracción acotada de cadenas ASCII y UTF-16LE; no ejecuta muestras."""
from pathlib import Path
import re

CHUNK = 1024 * 1024
MAX_RESULTS = 1000
MAX_STRING_BYTES = 4096

def extract_strings(path: str | Path, min_length: int = 5, max_results: int = 200) -> list[dict]:
    if type(min_length) is not int or not 4 <= min_length <= 128:
        raise ValueError("min_length debe estar entre 4 y 128.")
    if type(max_results) is not int or not 1 <= max_results <= MAX_RESULTS:
        raise ValueError("max_results debe estar entre 1 y 1000.")
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError("Se requiere archivo regular.")
    # Regex sobre bloques solapados: conserva offsets y evita cargar archivos completos.
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    results = []
    overlap = MAX_STRING_BYTES + 2
    with p.open("rb") as f:
        offset = 0
        tail = b""
        while True:
            block = f.read(CHUNK)
            if not block: break
            data = tail + block
            base = offset - len(tail)
            safe_end = len(data) if len(block) < CHUNK else max(0, len(data) - overlap)
            for kind, regex, codec in (("ASCII", ascii_re, "ascii"), ("UTF-16LE", wide_re, "utf-16le")):
                for match in regex.finditer(data):
                    if match.start() >= safe_end: continue
                    if len(results) >= max_results: break
                    raw = match.group()[:MAX_STRING_BYTES]
                    results.append({"offset": base + match.start(), "encoding": kind,
                                    "value": raw.decode(codec, "replace"),
                                    "truncated": len(match.group()) > MAX_STRING_BYTES})
            if len(results) >= max_results: break
            tail = data[-overlap:]
            offset += len(block)
    results.sort(key=lambda x: (x["offset"], x["encoding"]))
    return results[:max_results]
