"""C3: bitácora de custodia con hashes encadenados; sin firmas digitales."""
from __future__ import annotations
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
from .file_utils import secure_open_file

MAX_FILE = 2 * 1024 * 1024
MAX_EVENTS = 10000
ACTIONS = {"acquired", "transferred", "examined", "stored", "verified", "released"}

class CustodyError(ValueError):
    """Error durante la custodia de evidencia con código de estado."""
    def __init__(self, message: str, state: str = "error"):
        super().__init__(message)
        self.state = state

def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _hash_file(path: str | Path) -> tuple[str, int]:
    p = Path(path)
    stream = secure_open_file(p, max_size=MAX_FILE, purpose="evidence hashing")
    h = sha256()
    size = 0
    with stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
            size += len(block)
    return h.hexdigest(), size

def register_evidence(evidence_id: str, path: str | Path, actor: str, timestamp: str | None = None) -> dict:
    if not isinstance(evidence_id, str) or not 1 <= len(evidence_id.strip()) <= 128:
        raise CustodyError("Identificador inválido.", state="error")
    try:
        digest, size = _hash_file(path)
    except Exception as exc:
        raise CustodyError(f"Error al hashear evidencia: {exc}", state="error") from exc
    record = {
        "schema_version": 1,
        "evidence_id": evidence_id.strip(),
        "original_path": str(Path(path).absolute()),
        "size_bytes": size,
        "sha256": digest,
        "events": []
    }
    return append_event(record, "acquired", actor, "Registro inicial de evidencia", timestamp)

def append_event(record: dict, action: str, actor: str, note: str, timestamp: str | None = None) -> dict:
    verify_chain(record)
    if action not in ACTIONS:
        raise CustodyError("Acción de custodia inválida.", state="error")
    if not isinstance(actor, str) or not 1 <= len(actor.strip()) <= 128:
        raise CustodyError("Responsable inválido.", state="error")
    if not isinstance(note, str) or len(note) > 2048:
        raise CustodyError("Nota inválida.", state="error")
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise CustodyError("Timestamp inválido.", state="error") from exc
    if dt.tzinfo is None or dt.utcoffset().total_seconds() != 0:
        raise CustodyError("Se requiere UTC.", state="error")
    timestamp = dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if len(record["events"]) >= MAX_EVENTS:
        raise CustodyError("Límite de actuaciones alcanzado.", state="error")
    updated = {**record, "events": [*record["events"]]}
    previous = updated["events"][-1]["entry_hash"] if updated["events"] else None
    event = {"sequence": len(updated["events"]) + 1, "action": action,
             "actor": actor.strip(), "note": note, "timestamp_utc": timestamp,
             "previous_hash": previous}
    event["entry_hash"] = sha256(_canonical({"evidence_id": updated["evidence_id"], **event})).hexdigest()
    updated["events"].append(event)
    return updated

def verify_chain(record: dict) -> dict:
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        raise CustodyError("Registro C3 inválido.", state="error")
    if not isinstance(record.get("evidence_id"), str) or not record["evidence_id"]:
        raise CustodyError("ID de evidencia inválido.", state="error")
    digest = record.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise CustodyError("Hash de evidencia inválido.", state="error")
    events = record.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise CustodyError("Eventos inválidos.", state="error")
    previous = None
    for i, event in enumerate(events, 1):
        if not isinstance(event, dict) or event.get("sequence") != i or event.get("previous_hash") != previous:
            raise CustodyError(f"Secuencia de custodia inválida en evento {i}.", state="error")
        payload = {k:v for k,v in event.items() if k != "entry_hash"}
        expected = sha256(_canonical({"evidence_id": record["evidence_id"], **payload})).hexdigest()
        if event.get("entry_hash") != expected:
            raise CustodyError(f"Hash de actuación inválido en evento {i}.", state="error")
        previous = expected
    return {"chain_valid": True, "events": len(events), "head_hash": previous}

def verify_evidence(record: dict, path: str | Path) -> dict:
    chain = verify_chain(record)
    try:
        actual, size = _hash_file(path)
    except Exception as exc:
        raise CustodyError(f"Error al verificar evidencia: {exc}", state="error") from exc
    state = "completed"
    reason = None
    if not actual == record["sha256"]:
        state = "error"
        reason = "El hash de la evidencia no coincide con el registro de custodia."
    elif size != record["size_bytes"]:
        state = "error"
        reason = "El tamaño de la evidencia no coincide con el registro de custodia."
    return {
        "state": state,
        **chain,
        "evidence_hash_matches": actual == record["sha256"],
        "size_matches": size == record["size_bytes"],
        "actual_sha256": actual,
        "reason": reason,
        "limitations": [
            "La cadena detecta cambios internos, pero no acredita autoría ni evita reescribir toda la bitácora.",
            "Para custodia verificable externamente se requieren firmas, sellado temporal y almacenamiento inmutable."
        ],
    }

def save_new(record: dict, destination: str | Path) -> None:
    verify_chain(record)
    p = Path(destination)
    with p.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write("\n")

def load_record(path: str | Path) -> dict:
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_FILE:
        raise CustodyError("Archivo de custodia inválido o demasiado grande.", state="error")
    try:
        record = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CustodyError("Archivo de custodia no es JSON válido.", state="error") from exc
    verify_chain(record)
    return record
