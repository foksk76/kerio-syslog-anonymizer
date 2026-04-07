# Release Notes

## v0.2.0

## Operational Changes

- Added optional Kerio Connect API log export mode to `kerio_anonymizer.py`.
- Added `.env.example` with documented Kerio API connection settings.
- The anonymizer can now fetch a Kerio Connect log through the Admin API and anonymize it without requiring a pre-existing local input text file.
- README documentation now follows the `C:\Git\README_TEMPLATE*` project-family template.
- Added `README.ru.md` as the Russian quick-onboarding README aligned with the English README.

## Validation

- `python -m py_compile kerio_anonymizer.py` completed successfully.
- `python kerio_anonymizer.py --help` completed successfully.
- File-mode smoke test completed successfully with a temporary input file.
- Kerio API mode reached the expected network failure path with an unavailable test URL.
- Kerio API mode completed successfully against `kerio.lo` using `.env` plus `--kerio-insecure`.
- Real Kerio API credentials were checked and were not written to tracked project files.

## Engineer Notes

- Use `--kerio-fetch-log` to fetch logs from Kerio Connect API.
- Configure `KERIO_API_URL`, `KERIO_API_USER`, and `KERIO_API_PASSWORD` in `.env`; keep `.env` out of git.
- For lab Kerio servers with self-signed TLS certificates, either set `KERIO_API_INSECURE=true` in `.env` or pass `--kerio-insecure`.
- `Logs.exportLogRelative(..., PlainText)` is used for API export.
- `mapping.json` was refreshed by the live Kerio API run and still stores hashed real keys mapped to fake values.
