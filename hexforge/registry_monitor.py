"""NEXA Registry Monitor: offline triage of exported Sysmon registry events.

This module does not install a collector, monitor live registry access or execute samples.
"""
import json
from pathlib import Path
from .file_utils import validate_file_path

EVENTS = {12: "registry_object_created_or_deleted", 13: "registry_value_set", 14: "registry_object_renamed"}

# Persistence paths defined as component sequences to avoid substring false positives
PERSISTENCE_PATHS = {
    "run": ["software", "microsoft", "windows", "currentversion", "run"],
    "runonce": ["software", "microsoft", "windows", "currentversion", "runonce"],
    "services": ["system", "currentcontrolset", "services"],
    "winlogon": ["software", "microsoft", "windows nt", "currentversion", "winlogon"],
    "ifeo": ["software", "microsoft", "windows nt", "currentversion", "image file execution options"],
}

def _split_registry_path(path: str) -> list[str]:
    """Split registry path into normalized components."""
    # Remove leading/trailing backslashes and normalize
    normalized = path.strip("\\").replace("/", "\\").casefold()
    return normalized.split("\\")

def _matches_persistence_pattern(path_components: list[str], pattern_components: list[str]) -> bool:
    """Check if path components contain pattern sequence (must be consecutive)."""
    if len(pattern_components) > len(path_components):
        return False
    # Look for exact consecutive sequence match
    for i in range(len(path_components) - len(pattern_components) + 1):
        if path_components[i:i+len(pattern_components)] == pattern_components:
            return True
    return False

def classify_registry_event(event: dict) -> dict:
    """Classify an already-normalized event, preserving source uncertainty."""
    if not isinstance(event, dict): raise ValueError("El evento debe ser un objeto JSON.")
    event_id = event.get("event_id")
    if type(event_id) is not int or event_id not in EVENTS:
        raise ValueError("Solo eventos Sysmon 12, 13 y 14.")
    target = event.get("target_object", "")
    if not isinstance(target, str) or not target.strip() or len(target) > 8192:
        raise ValueError("target_object inválido.")

    # Split and normalize path
    path_components = _split_registry_path(target)

    # Check against persistence patterns
    matches = []
    for name, pattern in PERSISTENCE_PATHS.items():
        if _matches_persistence_pattern(path_components, pattern):
            matches.append(name)

    return {
        "event_id": event_id,
        "operation": EVENTS[event_id],
        "timestamp_utc": event.get("timestamp_utc"),
        "process_guid": event.get("process_guid"),
        "image": event.get("image"),
        "target_object": target,
        "details": event.get("details"),
        "possible_persistence_location": bool(matches),
        "matched_rules": matches,
        "assessment": "review" if matches else "informational",
        "persistence_confirmed": False,
        "execution_confirmed": False,
        "source": "normalized_sysmon_export",
        "limitations": [
            "No se capturan lecturas generales del registro.",
            "Un evento de escritura no demuestra persistencia efectiva.",
            "La ausencia de eventos no demuestra ausencia de actividad.",
            "La configuración de Sysmon y la cobertura de telemetría determinan qué se observa.",
        ],
    }

def analyze_export(path: str | Path) -> dict:
    """Read bounded JSON array of normalized Sysmon records without modifying evidence."""
    source = validate_file_path(path, must_exist=True, max_size=8 * 1024 * 1024, purpose="registry export")
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, list) or len(data) > 10000:
        raise ValueError("Se requiere una lista de hasta 10000 eventos.")
    results = [classify_registry_event(event) for event in data]
    return {"module": "Registry & Persistence Monitor — offline MVP",
            "events": results, "count": len(results),
            "review_count": sum(e["assessment"] == "review" for e in results),
            "live_monitoring": False, "execution_performed": False}
