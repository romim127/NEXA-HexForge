# Post-Execution Forensics & Persistence Analysis

**Status:** architecture proposal, not an implemented NTFS parser or live collector.

## Goal

Correlate historical filesystem metadata, Windows persistence mechanisms, runtime telemetry and existing NEXA-HexForge Prefetch/Amcache evidence to reconstruct potentially deleted executable activity without claiming that any artifact is guaranteed to exist.

## NTFS evidence inputs (read-only)

- **$MFT:** file-record identifiers, parent references, names, flags, allocation state, timestamps and data runs where available. A deleted record can be reused.
- **$Extend/$UsnJrnl:$J:** change journal entries, including delete-related reason flags, with journal ID and USN. Journal records can roll over or be disabled.
- **$LogFile:** NTFS transactional log, interpreted carefully: log operations are not a universal or permanent record of every user-level action.
- **Unallocated space:** recovery is conditional on overwriting, allocation, filesystem behavior, encryption, SSD TRIM and acquisition conditions.
- **$Recycle.Bin:** where applicable; bypassing the recycle bin leaves a different artifact pattern.

Never state that deleting a binary always preserves its full contents or a recoverable file record. Separate metadata evidence from content recovery. Support raw forensic images or verified exports, not live writes to evidence disks.

## Persistence inputs

- Registry Run / RunOnce (HKCU and HKLM, including WOW6432Node considerations)
- User and common Startup folders, shortcuts and targets
- Scheduled Tasks (Task Scheduler operational events, task XML, registry TaskCache, when available)
- Windows services and other extensible persistence locations

Record current state separately from historical creation/change/deletion events. An entry's existence is not proof it executed. A missing entry does not rule out past persistence.

## Evidence schema (planned)

Every observation should include:
- evidence ID, acquisition source, SHA-256 and chain-of-custody reference
- source format, parser version, acquisition time and time zone
- original timestamps and normalized UTC timestamps
- artifact location, file reference/record ID, path, process identity if independently known
- operation and outcome, provenance, confidence and parser limitations
- raw source record reference for analyst verification

Correlate on independent identifiers and temporal proximity, while tracking uncertainty, clock drift, timestamp manipulation and incomplete telemetry.

## Planned milestones

1. Define immutable evidence records and fixtures from synthetic NTFS/registry/task exports.
2. Build bounded, read-only normalized importers and validation tests.
3. Add NTFS metadata/journal correlation and timeline, with provenance.
4. Add Startup/Run/RunOnce/Task persistence triage, including deleted entries when historical evidence exists.
5. Join with Prefetch, Amcache, Sysmon and Runtime Monitor observations.
6. Produce a human-reviewable report distinguishing observed facts, hypotheses and unsupported conclusions.

## Security boundaries

Authorized lab or lawful forensic evidence only. No automatic execution of suspicious binaries, no evidence modification, no automatic restoration of recovered payloads, and no destructive remediation. Preserve source evidence and document acquisition constraints.
