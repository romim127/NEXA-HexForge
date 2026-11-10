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
| C2 · Forensic Timeline | Prototype | UTC event ordering, cross-source temporal associations, match basis and confidence labels |
| C3 · Evidence Provenance | Prototype | SHA-256 evidence registration, hash-linked custody events, integrity verification |
| Academy A1 · Base Converter | Prototype | HEX ⇄ binary, decimal contributions and interactive explanations |
| Academy A2 · Byte Inspector | Prototype | Local file offsets, clickable bytes, 8-bit weights, ASCII and decimal |
| Academy A3 · PE Header Explorer | Prototype | Explain MZ, e_lfanew, PE signature, machine, entry RVA, image base and sections |
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

C2 cross-source timeline:

```bash
python -m hexforge.timeline_cli evidence-export.csv --window 300 --report correlated-timeline.json
```

**C2 interpretation:** matching path or hash and time proximity indicate an association, never automatic proof of execution. Time fields retain exporter-specific meaning.

## C3 — Evidence provenance and custody

Register a local evidence file without executing it:

```bash
python -m hexforge.custody_cli register evidence.bin --id CASE-001 --actor "Analyst" --report custody.json
python -m hexforge.custody_cli verify custody.json evidence.bin
```

C3 verifies SHA-256 of evidence and a hash-linked event log. **This is tamper-evident only against partial edits**: without external signatures, immutable storage and trusted timestamps, the log is not legally authenticated or resistant to full rewriting. The original evidence is read-only; custody JSON is created as a new file, never overwritten.

## ♾️ NEXA Hex Academy — Educational Calculator

**[Open the interactive educational frontend](web/academy.html)** (download/serve the repository locally to run the page with JavaScript). Supports HEX → binary/decimal and binary → HEX, nibble-by-nibble with place-value contributions.

```bash
python -m hexforge.academy_cli AF
python -m hexforge.academy_cli 10101111 --from-base bin
```

Example: **AF₁₆ = 1010 1111₂ = 10 × 16¹ + 15 × 16⁰ = 175₁₀**.

## Academy A2 — Byte Inspector

**[Open Byte Inspector](web/byte-inspector.html)** — select a local file and an offset, read up to 32 bytes in-browser, then click any byte to inspect its HEX, binary weights, decimal and printable ASCII. The browser reads only a small local slice and does not upload or execute samples.

```bash
python -m hexforge.byte_academy_cli sample.bin --offset 0x0
```

For example, `4D` = `01001101` = `64 + 8 + 4 + 1` = `77` = ASCII `M`. The inspector is educational and does not establish maliciousness or execution.

## Academy A3 — PE Header Explorer

**[Open PE Header Explorer](web/pe-explorer.html)** — browser-only, local-file PE32/PE32+ structural learning: DOS MZ, `e_lfanew`, `PE\\0\\0`, machine, entry RVA, image base, and sections. A bounded 1 MiB header read; no binary execution or upload.

```bash
python -m hexforge.pe_academy_cli sample.exe
```

The educational explanation distinguishes **RVA from physical file offset** and explicitly avoids inferring execution or maliciousness from static fields. This prototype is not a complete PE validator.

## Visual identity

The Infinity SVG above is the repository's current vector brand asset. The detailed neon-cyan/violet concept artwork is the reference for the future frontend; implementation will use dark panels, readable monospace typography and separate static/dynamic/evidence views.

## Tests

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs Python 3.10, 3.12 and 3.13. Inspect its actual status before claiming tests passed.

See [architecture and limitations](docs/ARCHITECTURE.md).

**THERE IS NO FINAL VERSION. THERE IS ONLY EVOLUTION.**

**♾️ AI assists. Human verifies. Human decides.**
