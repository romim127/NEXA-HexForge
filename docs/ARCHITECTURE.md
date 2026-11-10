# NEXA HexForge — Architecture v0.1

## Principles
- Read-only static inspection; never execute untrusted files in the core.
- Hash evidence before analysis, record UTC observation time, preserve original evidence.
- Distinguish observed facts, inferred indicators, and unverified hypotheses.
- No upload of evidence to external services by default.
- Reports are reproducible and must state limitations and provenance.

## Roadmap
- **A · Binary Inspector:** streaming SHA-256/SHA-512, magic bytes, hex/ASCII preview, entropy. v0.1 implemented.
- **B · Executable Structure:** validated PE/ELF/Mach-O parsers, sections, imports, signatures, bounds checks.
- **C · Windows Artifact Correlator:** Prefetch, Amcache, ShimCache, EVTX, SRUM, MFT and USN, with source-specific interpretation.
- **D · Dynamic Analysis:** isolated, disposable, instrumented VM with explicit operator approval; no automatic execution.
- **E · Post-Execution Reconstruction:** before/after snapshots, process tree, filesystem/registry/network events, confidence and timestamps.
- **F · Evidence & Reporting:** chain of custody, provenance, timeline, JSON/DOCX/PDF and reproducible case packages.

## Threat model
Samples are untrusted inputs. Parser limits, input validation, no network access and resource limits are mandatory before handling adversarial corpora. Static results never establish execution or maliciousness by themselves.

## Verification
Run: `python -m unittest discover -s tests -v`
CLI: `python -m hexforge path/to/sample.bin --report analysis.json`
