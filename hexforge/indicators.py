"""Indicadores explicables de secciones PE: señales, no veredictos."""
from pathlib import Path
from collections import Counter
from math import log2
from .pe import inspect_pe

def _entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    return -sum((n/len(data))*log2(n/len(data)) for n in counts.values())

def section_indicators(path: str | Path) -> dict:
    pe = inspect_pe(path)
    findings = []
    sections = []
    with Path(path).open("rb") as f:
        for s in pe["sections"]:
            if s["raw_size"] > 64 * 1024 * 1024:
                findings.append({"section": s["name"], "rule": "large_section_skipped",
                                 "severity": "informational", "reason": "Sección supera el límite de lectura de 64 MiB."})
                continue
            f.seek(s["raw_offset"])
            data = f.read(s["raw_size"])
            e = round(_entropy(data), 4)
            sections.append({"name": s["name"], "entropy": e, "raw_size": s["raw_size"]})
            if s["executable"] and s["writable"]:
                findings.append({"section": s["name"], "rule": "writable_executable",
                                 "severity": "review", "reason": "La sección tiene permisos de escritura y ejecución."})
            if len(data) >= 256 and e >= 7.2:
                findings.append({"section": s["name"], "rule": "high_entropy",
                                 "severity": "review", "reason": "Entropía elevada; también puede indicar compresión o datos legítimos."})
    return {"sections": sections, "indicators": findings, "verdict": "not_determined",
            "execution_performed": False, "limitations": ["Los indicadores no demuestran malware.",
            "La entropía se calcula sobre bytes en disco, no memoria de ejecución."]}
