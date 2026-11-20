"""Academy A4: entropía Shannon explicada; indicador, no diagnóstico."""
from collections import Counter
from math import log2
from pathlib import Path
from .pe import inspect_pe
from .file_utils import secure_open_file

MAX_SAMPLE = 1024 * 1024

def explain_entropy(data: bytes) -> dict:
    if not isinstance(data, bytes): raise ValueError("Se requieren bytes.")
    if len(data) > MAX_SAMPLE: raise ValueError("Muestra superior a 1 MiB.")
    counts = Counter(data)
    n = len(data)
    terms = [{"byte_hex": f"{b:02X}", "count": count,
              "probability": count/n, "contribution": -(count/n)*log2(count/n)}
             for b,count in sorted(counts.items())] if n else []
    entropy = sum(item["contribution"] for item in terms)
    return {"sample_bytes": n, "unique_values": len(counts),
            "entropy_bits_per_byte": round(entropy,6),
            "max_theoretical_bits_per_byte": 8,
            "terms": terms,
            "formula": "H(X) = -Σ p(x) × log₂(p(x))",
            "interpretation": "La entropía mide diversidad estadística de bytes; valores altos pueden aparecer en datos comprimidos, cifrados o legítimos.",
            "malware_verdict": "not_determined"}

def inspect_section_entropy(path: str | Path, section_index: int) -> dict:
    if type(section_index) is not int or section_index < 0:
        raise ValueError("Índice de sección inválido.")
    p = Path(path)
    pe = inspect_pe(p)
    if section_index >= len(pe["sections"]): raise ValueError("Sección inexistente.")
    section = pe["sections"][section_index]
    stream = secure_open_file(p, purpose="entropy inspection")
    with stream:
        stream.seek(section["raw_offset"])
        sample = stream.read(min(section["raw_size"], MAX_SAMPLE))
    result = explain_entropy(sample)
    result.update({"section": section["name"], "section_index": section_index,
                   "section_raw_size": section["raw_size"], "sample_truncated": section["raw_size"] > MAX_SAMPLE,
                   "permissions": {"readable": bool(int(section["characteristics"],16)&0x40000000),
                                   "writable": section["writable"], "executable": section["executable"]},
                   "permission_note": "W+X requiere revisión contextual; no implica malware.",
                   "execution_performed": False})
    return result
