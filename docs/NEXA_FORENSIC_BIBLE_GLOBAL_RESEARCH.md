# NEXA Forensic Bible — Global malware anatomy research map

Research baseline: 2026-11-10. This is a **curated public-source research map**, not an exhaustive inventory of the internet, deep web or dark web. No malicious samples or illicit sources were collected.

## Core taxonomy

| Domain | Inside a sample / source | Questions for analyst | NEXA module |
|---|---|---|---|
| Identity | magic, hashes, signing, metadata | actual type, provenance, tampering? | A2 / Semantic Hex |
| Containers | ZIP, nested archives, APK, installers | embedded payloads, paths, signatures? | Container Inspector (planned) |
| PE/COFF | MZ, e_lfanew, COFF, Optional Header, sections | architecture, entry point, RVA/raw offsets? | A3/A6 |
| PE directories | imports, exports, resources, TLS, reloc, debug, CLR, certificates | capabilities and load-time structures? | PE Deep Inspector (planned) |
| Executable code | instructions, CFG, functions, constants, indirect calls | which behavior can code implement? | Disassembler integration (planned) |
| Data | ASCII/UTF-16, embedded config, encrypted/compressed blobs | references, configuration, context? | A8 Strings / A4 entropy |
| Obfuscation | packers, overlays, high entropy, decoded strings | legitimate compression or concealment? | A4.1 / FLOSS integration (planned) |
| Scripts/docs | PowerShell, JS, VBA, macros, PDF actions, LNK | execution chain and embedded commands? | Document/script triage (planned) |
| ELF/Mach-O | program headers, symbols, dynamic libraries, entitlements | Linux/macOS executable structure? | Multi-format parser (planned) |
| Android | AndroidManifest.xml, DEX, lib/*.so, resources.arsc, assets | permissions vs actual code behavior? | APK Inspector (planned) |
| Runtime | process tree, registry, filesystem, memory, network | which operations were observed and with what outcome? | Registry Monitor / Runtime Monitor |
| Post-execution | MFT, USN, Prefetch, Amcache, scheduled tasks, Run keys | what persisted, what changed, what can be corroborated? | DFIR C1-C3 / planned NTFS |
| Incident response | scope, containment, credential exposure, recovery | what actions are justified, safe and verifiable? | Guided Bible PB-001 |

## Analyst knowledge-card schema

Each card: NEXA-ID, question, relevant bytes/fields, example with offset, calculation (hex/binary/endian), possible explanations, alternate benign explanations, evidence sources, next investigative step, safe containment guidance, limitations, ATT&CK reference (where relevant), authoritative citations, review/version metadata.

### Initial priority cards

- PE-001 MZ -> e_lfanew -> PE validation.
- PE-002 Sections, permissions, entry point, RVA/raw translation.
- PE-003 Import table and dynamic resolution: capability is not execution.
- PE-004 Resources, TLS callbacks, relocations, signatures and overlays.
- OB-001 Entropy, packing and encryption: heuristic, not verdict.
- ST-001 ASCII, UTF-16, encoded/obfuscated strings.
- APK-001 Manifest permissions and component declarations.
- APK-002 DEX and native library relationship.
- RT-001 Registry reads vs writes, instrumentation coverage and gaps.
- RT-002 File open/write/delete and process lineage.
- DF-001 MFT/USN and conditional recovery.
- IR-001 Suspicious ZIP/EXE: preserve, triage, scope, contain, recover, verify.

## Sources and scope

- Microsoft PE/COFF format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Android apkanalyzer: https://developer.android.com/tools/apkanalyzer
- MITRE ATT&CK: https://attack.mitre.org/
- Mandiant capa: https://mandiant.github.io/capa/
- Mandiant FLOSS: https://github.com/mandiant/flare-floss
- YARA-X: https://virustotal.github.io/yara-x/docs/intro/getting-started/
- Sigma: https://sigmahq.io/sigma/
- Microsoft Process Monitor: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final

## Methodology and limits

Use vendor specifications for binary structure, independent tools and research for capability analysis, and NIST/ATT&CK for response/behavior mapping. Use public malware research and safely handled metadata, not uncontrolled sample execution. Dark-web claims should be treated as unverified intelligence until independently corroborated. Record source publication dates, ATT&CK versions and rule-set versions.

Never infer maliciousness solely from PE headers, high entropy, imports, strings, permissions or signing status. Distinguish **present in file**, **capability inferred**, **operation observed**, **impact corroborated** and **unknown**.
