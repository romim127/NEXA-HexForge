# Registry & Persistence Monitor — architectural proposal and offline MVP

## Scope

The first implemented component is an **offline** classifier of previously normalized
Sysmon event exports (12, 13, 14). It does not collect live events, install drivers,
intercept APIs, or run malware.

## Proposed telemetry pipeline

Windows collector (Sysmon / Windows Security / selected ETW providers)
→ event normalization and source metadata
→ persistence-rule engine
→ cross-source correlation with PE, Prefetch, Amcache and timeline
→ evidence custody and report.

Sysmon registry events 12/13/14 cover object create/delete, value set and rename.
They do **not** provide a comprehensive log of registry reads. Read monitoring needs
separate instrumentation and explicit coverage documentation. A missing event cannot
prove that a registry operation never happened.

## Normalized export contract

JSON array, at most 10,000 events and 8 MiB. Each item:

- `event_id`: integer 12, 13 or 14
- `target_object`: nonempty registry path
- `timestamp_utc`: optional UTC timestamp from source
- `process_guid`, `image`, `details`: optional original fields

Example:

```json
[{"event_id":13,"target_object":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Demo","timestamp_utc":"2026-11-10T04:00:00Z","image":"C:\\Lab\\sample.exe"}]
```

Run `python -m hexforge.registry_monitor_cli normalized-sysmon.json`.

## Evidence rules

A match to a persistence-related registry path is **review required**, not a malware
verdict. Separate attempted operation, recorded operation, persisted state and actual
execution. Preserve original EVTX/XML and source hash in future ingestion; this MVP
does not yet implement that acquisition or chain of custody.

## Security and privacy

Authorized endpoints only; least privilege, configurable event coverage, sensitive
value redaction, retention and access controls. Never store credentials, secrets or
raw registry value content unnecessarily. No automatic remediation or live sample
execution in the MVP.
