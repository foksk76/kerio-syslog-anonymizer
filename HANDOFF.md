# Handoff

## Current state

- Main script: `kerio_anonymizer.py`
- Dependency file: `requirements.txt`
- Mapping persistence: `mapping.json`
- Main English README: `README.md`
- Russian quick-onboarding README: `README.ru.md`
- Canonical release history: `CHANGELOG.md`

## Operational notes

- The script is intended for file-based anonymization of exported Kerio syslog text.
- Deterministic replacements depend on reusing the same `mapping.json`.
- Real keys in `mapping.json` are stored as `sha256(category:value)` hashes.
- `127.0.0.1` is intentionally preserved.
- Kerio Connect is proprietary vendor software and is not distributed by this repository.

## Documentation notes

- Keep `README.md` aligned with the `C:\Git\README_TEMPLATE*` family template.
- Keep `README.ru.md` aligned with `README.md` when README behavior changes.
- Keep `CHANGELOG.md` in English.
- Keep GitHub Release Notes in English.

## Recommended next operator checks

- Verify that Quick Start commands still match the real CLI behavior after code changes.
- Review whether the tracked `mapping.json` should remain public for this repository.
- Extend anonymization heuristics if new Kerio field formats appear in real datasets.
- Add CI checks for README examples and CLI smoke tests.
