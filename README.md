Language: [English](README.md) | [Русский](README.ru.md)

# Kerio Syslog Anonymizer

Deterministic anonymization of Kerio Connect syslog text files for safe sharing, public examples, and repeatable parser validation.

> **Project status:** Lab-friendly utility for safely preparing real Kerio syslog samples before public or semi-public use.

> **Language policy:** `README.md` is the main English README. `README.ru.md` is the main Russian translation for lab work and quick onboarding. Keep the language switcher as the first line in both files.

## Why this repository exists

Real Kerio Connect syslog can contain sensitive values such as email addresses, usernames, internal IP addresses, domains, subjects, display names, and personal names.

This repository receives raw syslog text, replaces supported sensitive values with deterministic fake values, and keeps a persistent mapping so repeated runs preserve correlation. That makes it easier to publish examples, reproduce parser behavior, and share troubleshooting datasets without exposing the original data.

## Project family

This repository is part of the **Kerio Connect Monitoring & Logging** project family:

1. [kerio-connect](https://github.com/foksk76/kerio-connect) - reproducible Kerio Connect lab environment
2. [kerio-logstash-project](https://github.com/foksk76/kerio-logstash-project) - parsing, normalization, and validation pipeline for Kerio syslog in ELK
3. [kerio-syslog-anonymizer](https://github.com/foksk76/kerio-syslog-anonymizer) - deterministic anonymization of real log data for safe public use and repeatable correlation

## Where this repository fits

This repository prepares raw Kerio syslog before the data is committed to a public repository, used in parser tests, or shared with another engineer.

```text
Kerio Connect -> raw syslog TXT -> kerio-syslog-anonymizer -> anonymized TXT -> Logstash / Elasticsearch / Kibana / documentation
```

The related repositories complement each other:

- `kerio-connect` provides a reproducible Kerio Connect lab.
- `kerio-logstash-project` parses, normalizes, enriches, and validates Kerio syslog in ELK.
- `kerio-syslog-anonymizer` prepares real logs for safe public sharing while preserving repeatable correlation.

## Main Usage Flow

1. Export or copy a raw Kerio syslog text file.
2. Run `kerio_anonymizer.py` with an input file, output file, and mapping file.
3. The script detects or uses the requested input encoding.
4. Supported sensitive values are replaced with deterministic fake values.
5. The anonymized output and `mapping.json` are written for later reuse and verification.

## Who This Is For

- Kerio Connect administrators who need to share safe log examples.
- DevOps, observability, or SecOps engineers who build parser and dashboard fixtures.
- Project contributors who need realistic anonymized data for repeatable validation.

## Architecture / Component Roles

1. **Source system** produces raw Kerio Connect syslog text.
2. **Anonymizer script** reads the text file and applies deterministic replacements.
3. **Mapping store** persists fake values in `mapping.json` using `sha256(category:value)` keys.
4. **Output artifact** stores anonymized syslog text for tests, documentation, or ELK ingestion.
5. **Verification commands** confirm that output files exist and mapping keys are hashed.

## Requirements

### Software

- OS: Windows, Linux, or another OS with Python support.
- Python: 3.11 or newer recommended.
- Python dependencies: install from `requirements.txt`.

### Hardware

- CPU: 1 vCPU is enough for small and medium files.
- RAM: 512 MB minimum, 1 GB recommended for larger files.
- Disk: enough free space for the input file, output file, and mapping file.

### Tested versions

| Component | Version | Notes |
|---|---|---|
| Python | 3.11.9 | Verified in local Windows environment |
| Python | 3.12.3 | Verified in Ubuntu 24.04 test container |
| Faker | From `requirements.txt` | Used for fake data generation |

## Repository structure

- `kerio_anonymizer.py` contains the CLI anonymizer.
- `requirements.txt` contains Python runtime dependencies.
- `.env.example` documents optional Kerio Connect API settings.
- `mapping.json` stores deterministic fake values with hashed real keys.
- `README.md` and `README.ru.md` describe onboarding in English and Russian.
- `CHANGELOG.md`, `HANDOFF.md`, and `NEXT_STEPS.md` describe project state and next steps.
- `CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, and `LICENSE` describe governance.

## Documentation language policy

- `README.md` is the main English source.
- `README.ru.md` is the main Russian translation for lab work and quick onboarding.
- The first line of both README files is the language switcher:

```md
Language: [English](README.md) | [Русский](README.ru.md)
```

- The Russian README follows the English README and does not document separate behavior.
- If the English README changes, update `README.ru.md` in the same release when feasible.
- `CHANGELOG.md` is maintained in English.
- `CONTRIBUTING.md` is maintained in English; Russian README changes are welcome when they preserve the meaning of the English version.

## Quick Start

Short path: create a local Python environment, anonymize one syslog text file, and confirm that the output and mapping files were created.

Work plan:

- prepare a Python virtual environment;
- install dependencies from `requirements.txt`;
- run the anonymizer against one input text file;
- confirm the output file and mapping file;
- inspect the first anonymized lines.

### 1. Clone the repository

```bash
git clone https://github.com/foksk76/kerio-syslog-anonymizer.git
cd kerio-syslog-anonymizer
```

If all is well:

- the current directory is the repository root;
- files such as `kerio_anonymizer.py`, `requirements.txt`, and `README.md` are present.

### 2. Prepare the environment

PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python kerio_anonymizer.py --help
```

Bash:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python kerio_anonymizer.py --help
```

**What you can edit**

- `--input` value: path to the source syslog text file.
- `--output` value: path for the anonymized output file.
- `--mapping` value: path to the mapping JSON file.
- `--input-encoding` value: use `cp1251` or `cp866` if the source is not UTF-8.
- `--seed` value: optional deterministic seed for fake generation.

**What matters**

- Reuse the same `mapping.json` when you need stable fake values across runs.
- Do not publish a mapping file unless you intentionally accept that it contains replacement history.
- `127.0.0.1` is intentionally preserved and is not anonymized.

### 3. Run the project

Create or copy a raw syslog text file named `input.txt` into the repository root, then run:

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json
```

If the input file uses a non-UTF-8 encoding, run:

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json --input-encoding cp1251
```

If all is well:

- the command finishes with `Done.`;
- the output path is printed;
- the mapping path is printed;
- `output.txt` and `mapping.json` exist after the run.

This quick start does not require a live Kerio Connect server. It can run with a saved text file or the minimal event shown below.

To fetch a source log from Kerio Connect API instead of reading `input.txt`, copy the environment example and edit it:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set at least these values in `.env`:

- `KERIO_API_URL`: Kerio Connect Admin API JSON-RPC URL, for example `https://kerio.example.local:4040/admin/api/jsonrpc/`.
- `KERIO_API_USER`: Kerio account allowed to read or export logs.
- `KERIO_API_PASSWORD`: password for that account.
- `KERIO_LOG_NAME`: log to export, for example `mail`.

Then run:

```powershell
python kerio_anonymizer.py --kerio-fetch-log --output output.txt --mapping mapping.json
```

If all is well:

- the script logs in to Kerio Connect API;
- the selected log is exported as plain text;
- `output.txt` and `mapping.json` are created or updated.

### 4. Verify the result

Check that the output and mapping files exist:

```powershell
python -c "from pathlib import Path; print(Path('output.txt').exists(), Path('mapping.json').exists())"
```

If all is well:

- the command prints `True True`.

Check that mapping keys are hashed:

```powershell
python -c "import json; data=json.load(open('mapping.json', encoding='utf-8')); category=next(iter(data.values()), {}); first=next(iter(category), 'empty'); print(first)"
```

If all is well:

- the printed key starts with `sha256:`;
- or the command prints `empty` when the input had no supported sensitive fields.

Inspect the first anonymized lines:

```powershell
Get-Content output.txt -TotalCount 5
```

If all is well:

- supported sensitive values are replaced with fake values;
- `127.0.0.1` remains unchanged if it exists in the source file.

### 5. Confirm the outcome

After the steps above:

- `output.txt` contains anonymized syslog text;
- `mapping.json` contains deterministic fake values keyed by hashed real values;
- repeated runs with the same mapping keep correlation stable.

## Audit Matrix Run

This repository does not have a separate audit or protocol matrix runner.

Use the verification commands in the Quick Start for this project. Audit and protocol validation belong to the wider Kerio lab and ELK pipeline repositories when they are present.

## Minimal Parser Event

```text
<22>1 2026-04-01T14:59:32+07:00 mx01.example.local audit - - - IMAP: User john.doe@example.local authenticated from IP address 10.150.90.11
```

Save it as `input.txt` to run the Quick Start without a real export file.

## Normalized Result

The exact fake values depend on the mapping file and seed, but the result should keep the event shape while replacing supported sensitive values:

```text
<22>1 2026-04-01T14:59:32+07:00 domain-7707198324.example.invalid audit - - - IMAP: User pamela_roberts@domain-8f60ae24ab.example.invalid authenticated from IP address 10.205.220.170
```

## Verification checklist

- [ ] Repository cloned successfully
- [ ] Environment prepared
- [ ] Dependencies installed from `requirements.txt`
- [ ] `python kerio_anonymizer.py --help` completed successfully
- [ ] `output.txt` was generated
- [ ] `mapping.json` was generated or updated
- [ ] Mapping keys start with `sha256:`
- [ ] Repeated runs keep deterministic replacements
- [ ] Russian README remains aligned with English README when README behavior changes

## Troubleshooting

### Problem: `Package 'Faker' is required`

**Symptoms**

- the script exits before processing the input file;
- the error mentions `Faker`.

**What to check**

- the virtual environment is active;
- dependencies from `requirements.txt` were installed.

**How to fix it**

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Problem: input text looks corrupted or unreadable

**Symptoms**

- Cyrillic or other non-ASCII text is garbled;
- subjects or names are not read as expected.

**What to check**

- the source file encoding may not be UTF-8.

**How to fix it**

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json --input-encoding cp1251
```

If that still looks wrong, try `--input-encoding cp866`.

### Problem: PowerShell blocks virtual environment activation

**Symptoms**

- `.venv\Scripts\Activate.ps1` is blocked by execution policy.

**What to check**

- the current PowerShell process execution policy.

**How to fix it**

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.venv\Scripts\Activate.ps1
```

### Problem: old mapping file still contains plain-text keys

**Symptoms**

- an older `mapping.json` contains original values instead of `sha256:` keys.

**What to check**

- the file may have been created before hashed-key normalization was added.

**How to fix it**

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json
```

If all is well:

- the mapping is normalized on save and future keys use the `sha256(category:value)` format.

## What This Project Does Not Do

- It does not deploy Kerio Connect.
- It does not run Logstash, Elasticsearch, Kibana, or Grafana.
- It does not provide a streaming syslog listener.
- It does not fully discover all possible PII in arbitrary text.
- It does not currently target IPv6 anonymization.
- It does not replace vendor documentation or formal data handling policy.

## What To Know Before Use

- Deterministic anonymization is intentional because dashboards, parser tests, and investigations need stable correlation.
- `mapping.json` stores hashed real keys, but it still represents replacement history and should be reviewed before publishing.
- `127.0.0.1` is preserved as-is.
- Input encoding matters for Cyrillic names and subjects.
- Kerio Connect is proprietary vendor software. This repository does not distribute Kerio Connect or vendor-restricted artifacts.

## Roadmap

See [NEXT_STEPS.md](./NEXT_STEPS.md)

## Changelog

See [CHANGELOG.md](./CHANGELOG.md)

Keep `CHANGELOG.md` canonical and English-only unless the repository explicitly decides otherwise.

## Handoff

See [HANDOFF.md](./HANDOFF.md)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

Contribution guidelines state that:

- English is the main language for project documentation and review;
- Russian README updates are welcome when they preserve the meaning of the English README;
- Russian documentation should help onboarding without changing documented behavior.

## GitHub Release Notes

GitHub Release Notes stay in English.

Use this shape for docs-only releases:

```md
## Operational Changes

- Documentation now follows the Kerio project family README template.
- Russian README content was aligned with the English README.
- No runtime behavior changed.

## Validation

- README language switchers were checked in both English and Russian documents.
- README headings were compared against the project template.
- `python kerio_anonymizer.py --help` completed successfully.

## Engineer Notes

- No runtime configuration change is required.
- Use the updated README when onboarding a new engineer or reviewing the anonymization workflow.
```

## Security

See [SECURITY.md](./SECURITY.md)

## Support

See [SUPPORT.md](./SUPPORT.md)

## License

See [LICENSE](./LICENSE)
