# Changes

## v0.1.0 - 2026-04-01

- Added the initial Kerio raw syslog anonymizer CLI.
- Added deterministic anonymization for emails, IPv4 addresses, usernames, subjects, full names, and domains.
- Added persistent mapping storage with `sha256`-hashed real keys instead of plain source values.
- Preserved `127.0.0.1` as-is during anonymization.
- Added input encoding fallbacks and documented usage in English.
- Added ignore rules for generated text files, local mapping output, and temporary SSH key files.
- Verified the workflow locally and in a temporary Ubuntu 24.04 test container on Proxmox.
