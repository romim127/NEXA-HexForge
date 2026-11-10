"""Normalización de observaciones forenses exportadas; no interpreta bases ESE/Prefetch crudas."""
from __future__ import annotations
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import csv
import json

SOURCES = {"prefetch", "amcache"}
MAX_ROWS = 100000
MAX_CSV_BYTES = 32 * 1024 * 1024
REQUIRED = {"source", "artifact_id", "file_path", "observed_time_utc"}
ALLOWED = REQUIRED | {"sha256", "note", "source_file", "event_type"}

def _timestamp(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Falta fecha UTC.")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Fecha inválida: se requiere ISO 8601 con zona horaria.") from exc
    if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise ValueError("Se requiere fecha con zona horaria UTC.")
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def normalize(row: dict, index: int) -> dict:
    if not isinstance(row, dict) or not REQUIRED.issubset(row):
        raise ValueError(f"Fila {index}: faltan campos obligatorios.")
    if any(not isinstance(v, str) or len(v) > 4096 for v in row.values() if v is not None):
        raise ValueError(f"Fila {index}: campo no textual o demasiado largo.")
    source = row["source"].strip().lower()
    if source not in SOURCES: raise ValueError(f"Fila {index}: fuente no admitida.")
    for field in ("artifact_id", "file_path"):
        if not row[field].strip(): raise ValueError(f"Fila {index}: {field} vacío.")
    event = row.get("event_type", "").strip().lower()
    if source == "amcache" and event not in ("", "file_reference"):
        raise ValueError("Amcache solo admite file_reference en este esquema.")
    if source == "prefetch" and event not in ("", "execution_indicator"):
        raise ValueError("Prefetch solo admite execution_indicator en este esquema.")
    digest = (row.get("sha256") or "").strip().lower()
    if digest and (len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
        raise ValueError(f"Fila {index}: SHA-256 inválido.")
    return {
        "source": source, "artifact_id": row["artifact_id"].strip(),
        "file_path": row["file_path"].strip(),
        "observed_time_utc": _timestamp(row["observed_time_utc"]),
        "sha256": digest or None, "note": row.get("note") or "",
        "event_type": "execution_indicator" if source == "prefetch" else "file_reference",
        "evidence_class": "execution_indicator" if source == "prefetch" else "presence_or_inventory",
        "interpretation": ("Prefetch puede respaldar una inferencia de ejecución, sujeto a validación del artefacto y contexto."
                           if source == "prefetch" else
                           "Amcache por sí solo no demuestra ejecución del archivo."),
        "source_file": row.get("source_file") or None,
        "raw_row_number": index,
    }

def load_export(path: str | Path) -> dict:
    p = Path(path)
    if p.is_symlink() or not p.is_file(): raise ValueError("Se requiere exportación CSV regular.")
    if p.stat().st_size > MAX_CSV_BYTES: raise ValueError("CSV supera 32 MiB.")
    raw = p.read_bytes()
    digest = sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("CSV debe estar codificado en UTF-8.") from exc
    rows = []
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames or not REQUIRED.issubset(reader.fieldnames):
        raise ValueError("Cabeceras CSV incompletas.")
    if len(reader.fieldnames) != len(set(reader.fieldnames)):
        raise ValueError("Cabeceras CSV duplicadas.")
    if any(name not in ALLOWED for name in reader.fieldnames):
        raise ValueError("Cabecera CSV desconocida.")
    for i, row in enumerate(reader, start=2):
        if i > MAX_ROWS + 1: raise ValueError("Límite de filas excedido.")
        if None in row: raise ValueError(f"Fila {i}: columnas extra.")
        rows.append(normalize(row, i))
    return {"schema_version": 1, "kind": "normalized_artifact_export",
            "source_export": str(p.absolute()), "source_sha256": digest,
            "records": rows, "record_count": len(rows),
            "limitations": ["La entrada es un CSV previamente exportado, no un artefacto Windows analizado directamente.",
                            "La autenticidad y correcta interpretación del exportador deben validarse por separado.",
                            "observed_time_utc es la fecha aportada por el exportador, no una hora de ejecución confirmada."]}

def timeline(export: dict) -> dict:
    if not isinstance(export, dict) or export.get("schema_version") != 1 or not isinstance(export.get("records"), list):
        raise ValueError("Exportación normalizada inválida.")
    events = sorted(export["records"], key=lambda r: (r["observed_time_utc"], r["source"], r["artifact_id"]))
    return {"schema_version": 1, "events": events, "count": len(events),
            "execution_confirmed": False,
            "conclusion": "La correlación de referencias y posibles indicadores no demuestra por sí sola una ejecución concreta.",
            "source_export_sha256": export["source_sha256"]}
