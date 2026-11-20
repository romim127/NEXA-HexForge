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

# Registry root aliases
REGISTRY_ROOTS = {
    "hkey_local_machine", "hklm",
    "hkey_current_user", "hkcu",
    "hkey_classes_root", "hkcr",
    "hkey_users", "hku",
    "hkey_current_config", "hkcc",
}

def _split_registry_path(path: str) -> tuple[list[str], str]:
    """Split registry path into normalized components, extracting root hive.

    Accepts both:
    - Full paths: HKEY_LOCAL_MACHINE\\SOFTWARE\\...
    - Relative paths: SOFTWARE\\... (assumed to be HKEY_LOCAL_MACHINE)
    - Forward slashes: /SOFTWARE/Microsoft/... (normalized and assumed HKEY_LOCAL_MACHINE)
    """
    # Normalize: slash sep → backslash, casefold, strip leading/trailing separators
    normalized = path.strip("\\/").replace("/", "\\").casefold()
    components = normalized.split("\\")

    if not components:
        raise ValueError("Empty registry path")

    # Native Sysmon registry paths use \REGISTRY\MACHINE or \REGISTRY\USER\<SID>.
    if len(components) >= 3 and components[0] == "registry":
        if components[1] == "machine":
            return ["hkey_local_machine"] + components[2:], "hkey_local_machine"
        if components[1] == "user" and len(components) >= 4:
            return ["hkey_users"] + components[2:], "hkey_users"
        raise ValueError("Unsupported native registry root")

    # Check if first component is a known registry root
    root = components[0].strip()
    if root in REGISTRY_ROOTS:
        # Full path with root specified
        return components, root
    elif root == "software" or root == "system":
        # Relative path without HKEY_ prefix; default to HKEY_LOCAL_MACHINE
        # Prepend HKEY_LOCAL_MACHINE to components for pattern matching
        return ["hkey_local_machine"] + components, "hkey_local_machine"
    else:
        raise ValueError(f"Unknown registry root or invalid path: {root}")

def _matches_persistence_pattern(path_components: list[str], pattern_components: list[str]) -> bool:
    """Check if path starts with the exact pattern sequence (excluding root hive).

    Registry persistence patterns are defined relative to the hive root.
    Examples:
    - Components: [hkey_local_machine, SOFTWARE, Microsoft, Windows, CurrentVersion, Run]
    - Pattern: [SOFTWARE, Microsoft, Windows, CurrentVersion, Run]

    This function matches the pattern starting after the root hive component.
    """
    # Skip the first component (root hive) if path includes it
    path_to_match = path_components
    if len(path_components) > 0 and path_components[0] in REGISTRY_ROOTS:
        path_to_match = path_components[1:]

    if len(pattern_components) > len(path_to_match):
        return False

    # Match pattern starting from position 0 of path_to_match
    return path_to_match[:len(pattern_components)] == pattern_components

def classify_registry_event(event: dict) -> dict:
    """Classify an already-normalized event, preserving source uncertainty."""
    if not isinstance(event, dict): raise ValueError("El evento debe ser un objeto JSON.")
    event_id = event.get("event_id")
    if type(event_id) is not int or event_id not in EVENTS:
        raise ValueError("Solo eventos Sysmon 12, 13 y 14.")
    target = event.get("target_object", "")
    if not isinstance(target, str) or not target.strip() or len(target) > 8192:
        raise ValueError("target_object inválido.")

    try:
        path_components, root_hive = _split_registry_path(target)
    except ValueError as e:
        return {
            "event_id": event_id,
            "operation": EVENTS[event_id],
            "timestamp_utc": event.get("timestamp_utc"),
            "process_guid": event.get("process_guid"),
            "image": event.get("image"),
            "target_object": target,
            "details": event.get("details"),
            "possible_persistence_location": False,
            "matched_rules": [],
            "assessment": "informational",
            "persistence_confirmed": False,
            "execution_confirmed": False,
            "source": "normalized_sysmon_export",
            "classification_note": str(e),
            "limitations": [
                "No se capturan lecturas generales del registro.",
                "Un evento de escritura no demuestra persistencia efectiva.",
                "La ausencia de eventos no demuestra ausencia de actividad.",
                "La configuración de Sysmon y la cobertura de telemetría determinan qué se observa.",
            ],
        }

    # Classify only locations meaningful for the corresponding hive.
    canonical_root = {
        "hklm": "hkey_local_machine", "hkcu": "hkey_current_user",
        "hkcr": "hkey_classes_root", "hku": "hkey_users",
        "hkcc": "hkey_current_config",
    }.get(root_hive, root_hive)
    allowed = {
        "hkey_local_machine": {"run", "runonce", "services", "winlogon", "ifeo"},
        "hkey_current_user": {"run", "runonce"},
        "hkey_users": {"run", "runonce"},
    }.get(canonical_root, set())
    match_components = path_components
    if canonical_root == "hkey_users":
        # HKEY_USERS requires a user SID immediately after the hive.
        if len(path_components) < 3 or not path_components[1].startswith("s-1-"):
            allowed = set()
        else:
            match_components = [path_components[0]] + path_components[2:]

    # Check against persistence patterns
    matches = []
    for name, pattern in PERSISTENCE_PATHS.items():
        if name in allowed and _matches_persistence_pattern(match_components, pattern):
            matches.append(name)

    return {
        "event_id": event_id,
        "operation": EVENTS[event_id],
        "timestamp_utc": event.get("timestamp_utc"),
        "process_guid": event.get("process_guid"),
        "image": event.get("image"),
        "target_object": target,
        "details": event.get("details"),
        "registry_root": canonical_root,
        "registry_root_assumed": target.lstrip("/\\").casefold().startswith(("software\\", "system\\", "software/", "system/")),
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
