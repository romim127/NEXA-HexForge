"""Indicadores explicables de secciones PE: señales, no veredictos."""
from pathlib import Path
from collections import Counter
from math import log2
from .pe import inspect_pe, PEError
from .file_utils import secure_open_file

def _entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    return -sum((n/len(data))*log2(n/len(data)) for n in counts.values())

class IndicatorsError(ValueError):
    """Error durante el análisis de indicadores con código de estado."""
    def __init__(self, message: str, state: str = "error"):
        super().__init__(message)
        self.state = state

def section_indicators(path: str | Path) -> dict:
    pe = inspect_pe(path)

    # Si el archivo no es PE válido, propagar el estado
    if pe.get("state") == "not_applicable":
        return {
            "state": "not_applicable",
            "reason": pe.get("reason", "El archivo no es un ejecutable PE válido; no hay secciones PE que evaluar."),
            "execution_performed": False,
        }
    if pe.get("state") == "error":
        raise IndicatorsError("Error en análisis PE previo.", state="error")

    findings = []
    sections = []
    f = secure_open_file(Path(path), purpose="indicator analysis")
    with f:
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

    state = "completed"
    reason = None
    if not findings:
        reason = "Análisis completado: sin indicadores detectados."

    return {
        "state": state,
        "sections": sections,
        "indicators": findings,
        "verdict": "not_determined",
        "reason": reason,
        "execution_performed": False,
        "limitations": [
            "Los indicadores no demuestran malware.",
            "La entropía se calcula sobre bytes en disco, no memoria de ejecución."
        ]
    }
