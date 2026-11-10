"""C2: correlación conservadora de eventos forenses normalizados."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from hashlib import sha256
import json

SUPPORTED = {"prefetch", "amcache"}
MAX_EVENTS = 100000

def _time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("Fecha UTC requerida con sufijo Z.")
    try: return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc: raise ValueError("Fecha ISO 8601 inválida.") from exc

def _identity(event: dict) -> tuple:
    digest = event.get("sha256")
    if digest: return ("sha256", digest.lower())
    # Fallback is explicitly weaker; no identity claim based on basename alone.
    return ("path", event["file_path"].replace("/", "\\").casefold())

def correlate(export: dict, window_seconds: int = 300) -> dict:
    if type(window_seconds) is not int or not 0 <= window_seconds <= 86400:
        raise ValueError("Ventana inválida.")
    if not isinstance(export, dict) or export.get("schema_version") != 1:
        raise ValueError("Exportación C1 inválida.")
    events = export.get("records")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ValueError("Lista de eventos inválida.")
    digest = export.get("source_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(x not in "0123456789abcdef" for x in digest):
        raise ValueError("SHA-256 de procedencia inválido.")
    normalized = []
    for i, event in enumerate(events):
        if not isinstance(event, dict) or event.get("source") not in SUPPORTED:
            raise ValueError(f"Evento {i} inválido.")
        if not isinstance(event.get("file_path"), str) or not event["file_path"]:
            raise ValueError("Ruta inválida.")
        if not isinstance(event.get("artifact_id"), str) or not event["artifact_id"]:
            raise ValueError("ID de artefacto inválido.")
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
    return {
        "schema_version": 2, "source_export_sha256": digest,
        "window_seconds": window_seconds,
        "events": [event for _, _, event in normalized],
        "correlations": correlations,
        "correlation_count": len(correlations),
        "execution_confirmed": False,
        "limitations": [
            "Los timestamps reflejan semántica del exportador, no necesariamente la misma clase de evento.",
            "Coincidencia de SHA-256 o ruta y proximidad temporal no prueban causalidad.",
            "Los niveles de confianza son reglas descriptivas preliminares, no probabilidades calibradas.",
            "No se fusionan identidades por nombre base; las rutas se comparan completas.",
            "Solo se correlacionan exportaciones normalizadas de Prefetch y Amcache.",
        ],
    }
