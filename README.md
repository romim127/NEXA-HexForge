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
| Registry Monitor · Offline MVP | Prototype | Classifies normalized Sysmon registry events 12/13/14 and possible persistence locations; live capture planned |
| Academy A1 · Base Converter | Prototype | HEX ⇄ binary, decimal contributions and interactive explanations |
| Academy A2 · Byte Inspector | Prototype | Local file offsets, clickable bytes, 8-bit weights, ASCII and decimal |
| Academy A3 · PE Header Explorer | Prototype | Explain MZ, e_lfanew, PE signature, machine, entry RVA, image base and sections |
| Academy A4 · PE Entropy Lab | Prototype | Shannon entropy, byte frequencies, section flags and step-by-step formula |
| Academy A5 · Import Intelligence | Prototype | DLLs, imported functions, API explanations and evidence limitations |
| Academy A6 · RVA Mapping | Prototype | RVA-to-file-offset calculations, raw versus virtual data, guided PE section mapping |
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

## Academy A4 — PE Sections & Entropy Lab

**[Open the interactive entropy lab](web/entropy-lab.html)** — select a local PE file, inspect its sections and calculate Shannon entropy for up to 1 MiB of section data. The interface explains the contribution of each observed byte and declared R/W/X flags. No uploads or execution.

```bash
python -m hexforge.entropy_academy_cli sample.exe --section 0
```

Entropy is expressed in **bits per byte** (0–8). High entropy can be normal for compressed or encrypted data; W+X section flags are review indicators only. **Neither establishes malware or execution.** A section larger than 1 MiB is sampled, not fully measured.

## Academy A5 — PE Import Intelligence

**[Open the import intelligence lab](web/import-intelligence.html)** — inspect bounded static PE imports locally in the browser and review educational explanations of DLLs and APIs. No uploads or binary execution.

```bash
python -m hexforge.import_academy_cli sample.exe
```

A static import is a *declared dependency*, not an observed API call. APIs such as `VirtualAlloc`, `WriteProcessMemory` or `CreateRemoteThread` also have legitimate uses. Dynamic resolution, delay-load imports and runtime behavior are not covered. The frontend is a learning prototype and must not be treated as a complete forensic parser.

## Academy A6 — RVA & Memory Mapping Lab

**[Open interactive RVA calculator](web/rva-mapping.html)** — enter RVA, VirtualAddress, PointerToRawData, SizeOfRawData and VirtualSize, or load PE section metadata from a local file. The result shows each step and distinguishes mapped, virtual-only and unmapped addresses.

```bash
python -m hexforge.rva_academy_cli sample.exe --rva 0x1010
```

Formula (for RVA backed by raw section data): `FileOffset = PointerToRawData + (RVA - VirtualAddress)`. For example, `0x400 + (0x1010 - 0x1000) = 0x410`. This prototype does not model header mapping, loader behavior, ASLR or actual memory execution.

## Registry & Persistence Monitor — offline MVP

This initial component classifies **already normalized Sysmon JSON exports** for registry events 12/13/14. It is **not** a live monitor and does not record general registry reads. Path matches trigger contextual review, never a persistence or malware verdict.

```bash
python -m hexforge.registry_monitor_cli normalized-sysmon.json
```

See [Registry Monitor architecture and export contract](docs/REGISTRY_MONITOR_ARCHITECTURE.md). The future Windows collector, raw EVTX ingestion, event provenance, cross-source correlation and controlled telemetry coverage are not yet implemented.

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
