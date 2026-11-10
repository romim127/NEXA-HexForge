# NEXA HexForge — Architecture v0.2

## Principles
- Read-only static inspection; never execute untrusted files in the core.
- Hash evidence before analysis, record UTC observation time, preserve original evidence.
- Distinguish observed facts, inferred indicators, and unverified hypotheses.
- No upload of evidence to external services by default.
- Reports are reproducible and must state limitations and provenance.

## Roadmap
- **A · Binary Inspector:** streaming SHA-256/SHA-512, magic bytes, hex/ASCII preview, entropy. v0.1 implemented; v0.2 adds bounded offset-based HEX/ASCII rows.
- **B · Executable Structure:** v0.2 initial defensive PE32/PE32+ headers and section table with bounds checks; ELF/Mach-O, imports and signatures pending.
- **C · Windows Artifact Correlator:** Prefetch, Amcache, ShimCache, EVTX, SRUM, MFT and USN, with source-specific interpretation.
- **D · Dynamic Analysis:** isolated, disposable, instrumented VM with explicit operator approval; no automatic execution.
- **E · Post-Execution Reconstruction:** before/after snapshots, process tree, filesystem/registry/network events, confidence and timestamps.
- **F · Evidence & Reporting:** chain of custody, provenance, timeline, JSON/DOCX/PDF and reproducible case packages.

## Threat model
Samples are untrusted inputs. Parser limits, input validation, no network access and resource limits are mandatory before handling adversarial corpora. Static results never establish execution or maliciousness by themselves.

## Verification
Run: `python -m unittest discover -s tests -v`
CLI: `python -m hexforge path/to/sample.bin --report analysis.json`

## CLI v0.2
- `python -m hexforge evidence.bin --hex-offset 0x100 --hex-length 256 --report result.json`
- `python -m hexforge program.exe --pe --report pe-result.json`
- PE inspection is opt-in; an MZ signature alone is not accepted as a valid PE.
- Reports are created exclusively (`x` mode) to avoid overwriting existing evidence reports.
- v0.2 does not execute binaries, inspect imports, infer maliciousness, or collect post-execution traces.
