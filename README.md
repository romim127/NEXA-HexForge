<p align="center"><img src="assets/nexa-hexforge-infinity.svg" alt="NEXA HexForge — Infinity" width="100%"></p>

# ♾️ NEXA-HexForge

**Binary Intelligence · Static & Dynamic Malware Analysis · DFIR · Post-Execution Forensics**

Enterprise-oriented forensic analysis project by **NextGenAI / KNOVA**. Static modules do not execute samples. Dynamic analysis remains a future, separately isolated and operator-authorized capability.

> **Engineering rule:** No detection without context. No conclusion without evidence. No execution outside a controlled environment.

## Implemented modules

| Module | Status | Capability |
| --- | --- | --- |
| A · Binary Inspector | Prototype | SHA-256/512, HEX/ASCII offsets, bounded string extraction, entropy |
| B · PE Inspector | Prototype | PE32/PE32+ headers, sections, import directory, review indicators |
| C1 · Artifact Correlator | Prototype | Normalized Prefetch/Amcache CSV imports, source hashes, cautious timeline |
| D · Dynamic Lab | Planned | Isolated, instrumented, explicitly approved sample execution |
| E · Post-Execution | Planned | Multi-source timeline, corroboration, uncertainty, provenance |
| F · Reporting | Partial | JSON output; formal chain of custody and PDF/DOCX planned |

## Usage

Static inspection (does **not** execute sample):

```bash
python -m hexforge sample.exe --pe --imports --indicators --strings --report static-report.json
```

Hex view:

```bash
python -m hexforge sample.exe --hex-offset 0x100 --hex-length 256
```

Correlate previously exported and normalized CSV:

```bash
python -m hexforge.artifact_cli evidence-export.csv --report artifact-timeline.json
```

CSV required columns: `source,artifact_id,file_path,observed_time_utc`. Optional: `sha256,note,source_file,event_type`. Sources: `prefetch`, `amcache`. Timestamps must include UTC timezone, e.g. `2026-11-10T12:00:00Z`.

**Important:** C1 does not parse raw `.pf` files or raw Amcache hives. It processes a structured CSV produced by another tool. Prefetch is an execution *indicator*, not unconditional proof; Amcache file references alone do not prove execution. Timestamp meaning depends on the original exporter.

## Tests

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs Python 3.10, 3.12 and 3.13. Inspect its actual status before claiming tests passed.

See [architecture and limitations](docs/ARCHITECTURE.md).

**THERE IS NO FINAL VERSION. THERE IS ONLY EVOLUTION.**

**♾️ AI assists. Human verifies. Human decides.**
