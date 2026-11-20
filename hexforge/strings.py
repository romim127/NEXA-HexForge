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
    overlap = MAX_STRING_BYTES + 2
    seen_strings = set()  # Track seen (offset, encoding, value) to prevent duplicates

    with f:
        offset = 0
        tail = b""
        eof = False

        while not eof:
            block = f.read(CHUNK)
            eof = len(block) < CHUNK

            if not block:
                break

            # Combine tail from previous block with current block
            data = tail + block
            base = offset - len(tail)

            # For non-last blocks, only process up to safe_end to avoid duplicates
            safe_end = len(data) if eof else max(0, len(data) - overlap)

            for kind, regex, codec in (("ASCII", ascii_re, "ascii"), ("UTF-16LE", wide_re, "utf-16le")):
                for match in regex.finditer(data):
                    # Skip matches beyond safe_end (will be re-scanned in next block)
                    if not eof and match.start() >= safe_end:
                        continue

                    if len(results) >= max_results:
                        break

                    raw = match.group()[:MAX_STRING_BYTES]
                    str_offset = base + match.start()
                    decoded = raw.decode(codec, "replace")

                    # Create unique key to prevent duplicates
                    key = (str_offset, kind, decoded)
                    if key not in seen_strings:
                        seen_strings.add(key)
                        results.append({
                            "offset": str_offset,
                            "encoding": kind,
                            "value": decoded,
                            "truncated": len(match.group()) > MAX_STRING_BYTES
                        })

                if len(results) >= max_results:
                    break

            if len(results) >= max_results:
                break

            # For next iteration: keep the overlap region for boundary matching
            tail = data[-overlap:] if len(data) > overlap else data
            offset += len(block)

    results.sort(key=lambda x: (x["offset"], x["encoding"]))
    return results[:max_results]
