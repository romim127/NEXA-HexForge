"""C2: correlación conservadora de eventos forenses normalizados."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from hashlib import sha256
import json

SUPPORTED = {"prefetch", "amcache"}
MAX_EVENTS = 100000
MAX_CORRELATIONS = 10000

class TimelineError(ValueError):
    """Error durante el análisis de correlación con código de estado."""
    def __init__(self, message: str, state: str = "error"):
        super().__init__(message)
        self.state = state

def _time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TimelineError("Fecha UTC requerida con sufijo Z.", state="error")
    try: return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc: raise TimelineError("Fecha ISO 8601 inválida.", state="error") from exc

def _identity(event: dict) -> tuple:
    digest = event.get("sha256")
    if digest: return ("sha256", digest.lower())
    # Fallback is explicitly weaker; no identity claim based on basename alone.
    return ("path", event["file_path"].replace("/", "\\").casefold())

def correlate(export: dict, window_seconds: int = 300) -> dict:
    if type(window_seconds) is not int or not 0 <= window_seconds <= 86400:
        raise TimelineError("Ventana inválida.", state="error")
    if not isinstance(export, dict) or export.get("schema_version") != 1:
        raise TimelineError("Exportación C1 inválida.", state="error")
    events = export.get("records")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise TimelineError("Lista de eventos inválida.", state="error")
    digest = export.get("source_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(x not in "0123456789abcdef" for x in digest):
        raise TimelineError("SHA-256 de procedencia inválido.", state="error")
    normalized = []
    for i, event in enumerate(events):
        if not isinstance(event, dict) or event.get("source") not in SUPPORTED:
            raise TimelineError(f"Evento {i} inválido.", state="error")
        if not isinstance(event.get("file_path"), str) or not event["file_path"]:
            raise TimelineError("Ruta inválida.", state="error")
        if not isinstance(event.get("artifact_id"), str) or not event["artifact_id"]:
            raise TimelineError("ID de artefacto inválido.", state="error")
        when = _time(event.get("observed_time_utc"))
        normalized.append((when, i, event))
    normalized.sort(key=lambda x: (x[0], x[1]))
    groups = defaultdict(list)
    for when, index, event in normalized:
        groups[_identity(event)].append((when, index, event))
    correlations = []
    for key, group in groups.items():
        if len(group) < 2: continue
        for pos, (when, index, event) in enumerate(group):
            for later_time, later_index, later in group[pos+1:]:
                delta = int((later_time - when).total_seconds())
                if delta > window_seconds: break
                if event["source"] == later["source"]: continue
                match_type = key[0]
                if len(correlations) >= MAX_CORRELATIONS:
                    raise TimelineError("Demasiadas correlaciones; reduzca la ventana temporal o filtre eventos.", state="error")
                correlations.append({
                    "left_row": event.get("raw_row_number", index+1),
                    "right_row": later.get("raw_row_number", later_index+1),
                    "left_artifact": event["artifact_id"], "right_artifact": later["artifact_id"],
                    "match_basis": match_type, "time_delta_seconds": delta,
                    "corroboration": "cross_source_temporal_association",
                    "confidence": "moderate" if match_type == "sha256" else "low",
                    "execution_confirmed": False,
                    "interpretation": "Asociación temporal entre fuentes; no demuestra ejecución ni causalidad.",
                })

    state = "completed"
    reason = None
    if not correlations:
        reason = "Correlación completada: sin eventos correlacionados dentro de la ventana temporal."

    return {
        "state": state,
        "schema_version": 2,
        "source_export_sha256": digest,
        "window_seconds": window_seconds,
        "events": [event for _, _, event in normalized],
        "correlations": correlations,
        "correlation_count": len(correlations),
        "reason": reason,
        "execution_confirmed": False,
        "limitations": [
            "Los timestamps reflejan semántica del exportador, no necesariamente la misma clase de evento.",
            "Coincidencia de SHA-256 o ruta y proximidad temporal no prueban causalidad.",
            "Los niveles de confianza son reglas descriptivas preliminares, no probabilidades calibradas.",
            "No se fusionan identidades por nombre base; las rutas se comparan completas.",
            "Solo se correlacionan exportaciones normalizadas de Prefetch y Amcache.",
        ],
    }
