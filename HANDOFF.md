# Handoff

## Current state

- Main script: `kerio_anonymizer.py`
- Dependency file: `requirements.txt`
- Mapping persistence: `mapping.json`
- Documentation baseline: unified README structure for the Kerio project family

## Operational notes

- The script is intended for file-based anonymization of exported Kerio syslog text.
- Deterministic replacements depend on reusing the same `mapping.json`.
- Real keys in `mapping.json` are stored as `sha256(category:value)` hashes.
- `127.0.0.1` is intentionally preserved.

## Recommended next operator checks

- Verify that the documented Quick Start still matches the real CLI behavior after code changes.
- Review whether the tracked `mapping.json` should remain public for this repository.
- Extend heuristics if new Kerio field formats appear in real datasets.
