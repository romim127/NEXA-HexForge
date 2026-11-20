"""Inspección estática y reproducible de binarios, sin ejecución de muestras."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256, sha512
from math import log2
from pathlib import Path
import json
from .file_utils import secure_open_file

CHUNK = 1024 * 1024

def identify(header: bytes) -> str:
    if header.startswith(b"MZ"): return "PE candidate (MZ)"
    if header.startswith(b"\x7fELF"): return "ELF"
    if header.startswith(b"PK\x03\x04"): return "ZIP container"
    if header.startswith(b"%PDF-"): return "PDF"
    if header.startswith(b"\xca\xfe\xba\xbe"): return "Mach-O universal / Java class candidate"
    return "Unknown"

def entropy(counts: Counter, size: int) -> float:
    if not size: return 0.0
    return -sum((n / size) * log2(n / size) for n in counts.values() if n)

def inspect_file(path: str | Path, preview_bytes: int = 256, report_mode: str = "forense") -> dict:
    """Inspect file with optional privacy control.

    report_mode: "forense" includes absolute source_path for audit trail;
                 "shareable" removes source_path only; not full anonymization.
                 "redacted" removes source_path and byte previews, but retains hashes.
    """
    if type(preview_bytes) is not int or not 0 <= preview_bytes <= 4096:
        raise ValueError("preview_bytes debe estar entre 0 y 4096.")
    if report_mode not in ("forense", "shareable", "redacted"):
        raise ValueError("report_mode must be 'forense', 'shareable' or 'redacted'.")

    source = Path(path)
    stream = secure_open_file(source, purpose="file inspection")
    h256, h512, counts = sha256(), sha512(), Counter()
    size = 0
    preview = bytearray()
    with stream:
        while block := stream.read(CHUNK):
            h256.update(block); h512.update(block); counts.update(block)
            size += len(block)
            if len(preview) < preview_bytes:
                preview.extend(block[:preview_bytes-len(preview)])
    header = bytes(preview)

    report = {
        "schema_version": 1, "tool": "NEXA-HexForge",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "size_bytes": size,
        "sha256": h256.hexdigest(), "sha512": h512.hexdigest(),
        "file_signature": identify(header),
        "entropy_bits_per_byte": round(entropy(counts, size), 6),
        "hex_preview": header.hex(" "), "ascii_preview": "".join(chr(b) if 32 <= b <= 126 else "." for b in header),
        "execution_performed": False,
        "report_mode": report_mode,
    }

    # Include source_path only in forense mode (audit trail requirement)
    if report_mode == "forense":
        report["source_path"] = str(source.absolute())

    report["limitations"] = ["File signatures are preliminary; MZ alone does not validate a PE structure.",
                            "Entropy is not evidence of maliciousness.",
                            "No execution, sandboxing, network requests or Windows artifact collection was performed."]

    if report_mode == "redacted":
        # Preserve analytical metadata and hashes; omit all raw-byte previews.
        # Hashes can still correlate evidence and are not anonymous identifiers.
        report["hex_preview"] = ""
        report["ascii_preview"] = ""
        report["limitations"].append(
            "Redacted mode omits source_path and raw-byte previews, but SHA hashes "
            "can still identify or correlate files. Review remaining metadata "
            "before distribution; this is not guaranteed anonymization."
        )

    if report_mode == "shareable":
        report["limitations"].append(
            "Shareable mode removes source_path only. File previews can reveal "
            "sensitive bytes, and hashes can correlate evidence across datasets. "
            "This is not anonymization; review before external distribution."
        )

    return report

def write_report(report: dict, destination: str | Path) -> None:
    """Export caller-supplied JSON unchanged; no automatic sanitization.

    Arbitrary dictionaries bypass inspect_file's report_mode filtering.
    Review all fields before sharing with third parties.
    """
    target = Path(destination)
    with target.open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2, ensure_ascii=False)
        out.write("\n")
