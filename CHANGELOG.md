# Changelog

## v0.1.2 - 2026-04-05

- Refactored `README.md` to the unified Kerio project family structure.
- Added `CHANGELOG.md`, `HANDOFF.md`, and `NEXT_STEPS.md`.
- Added governance file links required by the project family standard.
- Cleaned documentation formatting to avoid template encoding artifacts.

## v0.1.1 - 2026-04-01

- Allowed `mapping.json` to be tracked because real keys are stored as `sha256(category:value)` hashes.
- Added a hashed `mapping.json` generated from the current anonymization workflow.

## v0.1.0 - 2026-04-01

- Added the initial Kerio raw syslog anonymizer CLI.
- Added deterministic anonymization for emails, IPv4 addresses, usernames, subjects, full names, and domains.
- Added persistent mapping storage.
- Preserved `127.0.0.1` as-is during anonymization.
- Added encoding fallbacks and initial English documentation.
