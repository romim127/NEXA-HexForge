# NEXA Forensic Bible — Guided Investigation & Response Engine

Status: **architecture and initial playbook specification**. No automated containment or execution is implemented.

## Purpose

Teach a defender, step by step, how to triage a suspicious ZIP/EXE, interpret bytes and PE structures, assess observed execution, reconstruct persistence and potential data exposure, and decide what to do next. A finding must link to evidence, uncertainty, analyst action and a safe response.

## Core workflow

1. **Triage and safety:** identify context, authority and incident priority; do not open or execute a suspicious attachment on a production endpoint. If active compromise is suspected, coordinate containment with incident response and preserve volatile evidence as feasible.
2. **Preserve:** retain original ZIP/EXE in controlled storage; document source, acquisition time, SHA-256, custody and whether the sample was executed. Never extract into an unsafe location or automatically run content.
3. **Static examination:** inspect archive entries and traversal/symlink risks, magic bytes, HEX/ASCII, endian fields, PE headers, sections, entropy, imports, strings, signatures and entry point. An import, string or high entropy alone does not prove malicious behavior.
4. **Execution evidence:** identify host, account, process lineage and timestamps. Correlate event logs, Sysmon where deployed, Prefetch/Amcache, registry and filesystem artifacts. Separate recorded activity from interpretation.
5. **Scope:** check persistence (Run/RunOnce, Startup, scheduled tasks, services), file changes (MFT/USN where available), network destinations and possible credential-access indicators. Never infer confirmed exfiltration from a network-capable import alone.
6. **Contain and recover:** use approved response procedures; preserve evidence before destructive changes when practical; isolate affected endpoints if warranted; revoke exposed sessions and rotate credentials from a trusted device when exposure is plausible; remove confirmed persistence, rebuild compromised hosts when warranted, patch entry point and monitor recurrence.
7. **Report:** what was observed, evidence identifiers, confidence, alternative explanations, what remains unknown, response actions and verification.

## Knowledge article contract

Each article has:
- unique NEXA ID and version
- title, analyst question, prerequisites and scope
- attack hypotheses, optional ATT&CK technique references with version and source
- byte-level explanation, API/OS operation interpretation and safe lab examples
- evidence sources, acquisition prerequisites and blind spots
- observable vs inferred vs confirmed outcomes
- decision tree: condition, next safe step, reason, expected result and escalation
- containment/remediation/verification guidance and risks
- citations, reviewer and last-reviewed date

ATT&CK is a reference taxonomy, not proof of technique attribution. Never claim the NEXA Bible is MITRE's own product.

## Initial guided playbook: suspicious ZIP or EXE

**PB-001: suspicious archive/executable**
- Received but not executed: quarantine securely; hash and inventory ZIP entries; inspect file signatures and PE; check provenance. Do not claim compromise.
- Opened/executed: preserve time and context; check process creation and host telemetry; identify persistence and file changes; evaluate network activity and account exposure; coordinate containment.
- File subsequently deleted: check NTFS metadata and journals, where available; distinguish deletion observation from self-deletion attribution; recovery may be impossible due to reuse, overwriting or TRIM.
- Suspicious Run key found: confirm exact path, timestamps, process correlation and current value; determine whether it launched; use approved containment/remediation and verify absence of recurrence.
- Suspicious API import found: explain capability, then require corroborating execution telemetry; do not call an import a syscall or proof of behavior.

## Guided investigation data model (future)

Case -> evidence -> observations -> hypotheses -> analyst decisions -> response actions -> verification.

Each edge must retain source identifiers, UTC timestamp, confidence, known blind spots and human approval. Suggested steps are recommendations, not automatic actions.

## Boundaries

- No malware execution outside an authorized isolated laboratory.
- No live containment, registry deletion, credential reset or disk modification without explicit operator approval and organizational policy.
- No claim of exhaustive syscall tracing: coverage depends on instrumentation, event configuration and loss.
- Prefer read-only acquisition and privacy-conscious handling of credential-related artifacts.
- Separate detection, impact assessment and confirmed data exfiltration.

## Implementation roadmap

K1: versioned knowledge articles and PB-001.
K2: rule-based next-step engine with explainable decisions and tests.
K3: contextual links from PE imports, strings, entropy, Registry Monitor and NTFS triage.
K4: analyst checklist, case state, provenance and evidence chain.
K5: report generator and review/approval workflow.
K6: offline-first GUI and optional ATT&CK mapping updates.
