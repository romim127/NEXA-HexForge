"""Extracción acotada de cadenas ASCII y UTF-16LE; no ejecuta muestras."""
from pathlib import Path
import re
from .file_utils import secure_open_file

CHUNK = 1024 * 1024
MAX_RESULTS = 1000
MAX_STRING_BYTES = 4096

def extract_strings(path: str | Path, min_length: int = 5, max_results: int = 200) -> list[dict]:
    if type(min_length) is not int or not 4 <= min_length <= 128:
        raise ValueError("min_length debe estar entre 4 y 128.")
    if type(max_results) is not int or not 1 <= max_results <= MAX_RESULTS:
        raise ValueError("max_results debe estar entre 1 y 1000.")
    p = Path(path)
    f = secure_open_file(p, purpose="string extraction")

    # Regex patterns with explicit quantifiers
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)

    results = []
    seen_offsets = set()  # Track (offset, encoding) to prevent duplicate reporting
    overlap = MAX_STRING_BYTES + 2

    with f:
        offset = 0
        tail = b""

        while True:
            block = f.read(CHUNK)
            if not block:
                break

            # Combine tail from previous block with current block
            data = tail + block
            base = offset - len(tail)
            is_last_block = len(block) < CHUNK

            for kind, regex, codec in (("ASCII", ascii_re, "ascii"), ("UTF-16LE", wide_re, "utf-16le")):
                for match in regex.finditer(data):
                    match_offset = base + match.start()
                    match_key = (match_offset, kind)

                    # Skip if already reported from previous chunk
                    if match_key in seen_offsets:
                        continue

                    if len(results) >= max_results:
                        break

                    raw = match.group()[:MAX_STRING_BYTES]
                    decoded = raw.decode(codec, "replace")

                    seen_offsets.add(match_key)
                    results.append({
                        "offset": match_offset,
                        "encoding": kind,
                        "value": decoded,
                        "truncated": len(match.group()) > MAX_STRING_BYTES
                    })

                if len(results) >= max_results:
                    break

            if len(results) >= max_results:
                break

            # Keep overlap region for next iteration
            if is_last_block:
                # Last block: no need to keep tail
                tail = b""
            else:
                # Keep the last 'overlap' bytes for boundary detection
                tail = data[-overlap:] if len(data) > overlap else data

            offset += len(block)

    results.sort(key=lambda x: (x["offset"], x["encoding"]))
    return results[:max_results]
