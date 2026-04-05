# Kerio Syslog Anonymizer

Deterministic anonymization of Kerio Connect syslog data for safe sharing, demos, and reproducible ELK work.

## Why this repository exists

Real Kerio Connect syslog often contains sensitive data: email addresses, usernames, internal IP addresses, domains, subjects, and personal names. That makes it hard to publish sample logs, share incidents with third parties, or build public dashboards and test datasets.

This repository exists to make that workflow safer and repeatable. It anonymizes raw syslog text while keeping replacements deterministic, so the same source value is always replaced with the same fake value across repeated runs. That matters when you want dashboards, parsing rules, correlation logic, and troubleshooting examples to remain consistent after anonymization.

## Project family

This repository is part of the **Kerio Connect Monitoring & Logging** project family:

1. [kerio-connect](https://github.com/foksk76/kerio-connect) - reproducible Kerio Connect lab environment
2. [kerio-logstash-project](https://github.com/foksk76/kerio-logstash-project) - parsing, normalization, and enrichment pipeline for Kerio syslog
3. [kerio-syslog-anonymizer](https://github.com/foksk76/kerio-syslog-anonymizer) - deterministic anonymization of real log data for safe public use

## Where this repository fits

This repository sits between log collection and public or semi-public reuse of logs.

Typical flow:

`Kerio Connect -> raw syslog export -> kerio-syslog-anonymizer -> safe sample dataset -> Logstash / Elasticsearch / Kibana / documentation`

It is especially useful when you want to:

- publish example logs without exposing original identities;
- keep stable identifiers for dashboards and parsing tests;
- share troubleshooting datasets with reduced disclosure risk.

## Main use cases

- Prepare real-world Kerio syslog for safe publication in Git repositories, blog posts, tickets, or demo labs.
- Generate deterministic anonymized datasets for parser development and regression checks.
- Share sample log files with teammates without disclosing original addresses, domains, or personal names.
- Preserve field-to-field correlation after anonymization for dashboards and investigations.

## Audience

- beginner DevOps engineers
- sysadmins and mail administrators
- homelab users
- SIEM / observability practitioners
- developers working on Kerio log parsing and enrichment

## Architecture / Flow

1. Input: a raw Kerio syslog `.txt` file.
2. Processing: regex- and field-based anonymization for supported data types.
3. Persistence: a `mapping.json` file stores `sha256(category:value)` keys mapped to deterministic fake values.
4. Output: an anonymized `.txt` file plus a reusable mapping file for future runs.

## Requirements

### Software

- Python 3.11 or newer
- `pip`
- packages from `requirements.txt`

### Hardware

- CPU: 1 vCPU is enough for small and medium files
- RAM: 512 MB minimum, 1 GB recommended for larger files
- Disk: enough free space for the input file, output file, and mapping file

### Tested versions

| Component | Version | Notes |
|---|---|---|
| Python | 3.11.9 | verified in local Windows environment |
| Python | 3.12.3 | verified in Ubuntu 24.04 test container |
| Faker | from `requirements.txt` | current anonymization dependency |

## Repository structure

```text
.
|-- README.md
|-- CHANGELOG.md
|-- HANDOFF.md
|-- NEXT_STEPS.md
|-- CONTRIBUTING.md
|-- SECURITY.md
|-- SUPPORT.md
|-- LICENSE
|-- CHANGES.md
|-- kerio_anonymizer.py
|-- requirements.txt
`-- mapping.json
```

Notes:

- `kerio_anonymizer.py` is the main CLI script.
- `mapping.json` is the persisted real-to-fake mapping file with hashed real keys.
- `CHANGES.md` currently exists as working project notes; the canonical public release history is tracked in [CHANGELOG.md](./CHANGELOG.md).

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/foksk76/kerio-syslog-anonymizer.git
cd kerio-syslog-anonymizer
```

Expected result:

- the repository is cloned locally;
- you are inside the `kerio-syslog-anonymizer` directory.

### 2. Prepare the environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python kerio_anonymizer.py --help
```

What you may need to edit:

- no source code changes are required;
- if your shell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass`;
- if your input file is not UTF-8, be ready to set `--input-encoding cp1251` or `--input-encoding cp866` in the run step.

Expected result:

- dependencies install successfully;
- `python kerio_anonymizer.py --help` prints usage information and exits without error.

### 3. Run the project

Create `input.txt` in the repository root. You can use the sample from [Example input](#example-input) below or replace it with your own exported Kerio syslog file.

Run the anonymizer:

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json
```

If the input file is encoded differently, run for example:

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json --input-encoding cp1251
```

Expected result:

- the script prints `Done.`;
- it shows the resolved input, output, and mapping file paths;
- `output.txt` and `mapping.json` are created or updated.

### 4. Verify the result

Check that the output and mapping files exist:

```powershell
python -c "from pathlib import Path; print(Path('output.txt').exists(), Path('mapping.json').exists())"
```

Expected result:

- the command prints `True True`.

Check that mapping keys are hashed and not stored as plain original values:

```powershell
python -c "import json; data=json.load(open('mapping.json', encoding='utf-8')); first=next(iter(next(iter(data.values()))), 'empty'); print(first)"
```

Expected result:

- the printed key starts with `sha256:` or the output is `empty` if the input had no supported sensitive fields.

Check that the anonymized file contains replaced values:

```powershell
Get-Content output.txt -TotalCount 5
```

Expected result:

- original addresses, usernames, domains, and private IP addresses are replaced with fake deterministic values;
- `127.0.0.1` remains unchanged if it exists in the input.

### 5. Example outcome

After a successful run you should have:

- `output.txt` with anonymized Kerio syslog content;
- `mapping.json` with hashed real keys mapped to fake values;
- stable replacements across repeated runs using the same mapping file.

## Example input

```text
<22>1 2026-04-01T14:59:31+07:00 mx01.example.local mail - - - Sent: Queue-ID: 69ccd05a-0001a3e2, Recipient: <john.doe@example.local>, Result: delayed, Status: 4.3.0 Recipient's mailbox busy, Remote-Host: 127.0.0.1, Msg-Id: <alert-123@example.local>
<22>1 2026-04-01T14:59:32+07:00 mx01.example.local audit - - - IMAP: User john.doe@example.local authenticated from IP address 10.150.90.11
<22>1 2026-04-01T14:59:33+07:00 mx01.example.local operations - - - {MOVE} User: john.doe@example.local, From: "Ivan Petrov" <john.doe@example.local>, Subject: "Payroll update"
```

## Example output

```text
<22>1 2026-04-01T14:59:31+07:00 domain-7707198324.example.invalid mail - - - Sent: Queue-ID: 69ccd05a-0001a3e2, Recipient: <bobby_vance@domain-8f60ae24ab.example.invalid>, Result: delayed, Status: 4.3.0 Recipient's mailbox busy, Remote-Host: 127.0.0.1, Msg-Id: <timothy-riley@domain-8f60ae24ab.example.invalid>
<22>1 2026-04-01T14:59:32+07:00 domain-7707198324.example.invalid audit - - - IMAP: User pamela_roberts@domain-8f60ae24ab.example.invalid authenticated from IP address 10.205.220.170
<22>1 2026-04-01T14:59:33+07:00 domain-7707198324.example.invalid operations - - - {MOVE} User: pamela_roberts@domain-8f60ae24ab.example.invalid, From: "Martin Borisov" <pamela_roberts@domain-8f60ae24ab.example.invalid>, Subject: "Calendar update"
```

## Verification checklist

- [ ] Repository cloned successfully
- [ ] Virtual environment created
- [ ] Dependencies installed from `requirements.txt`
- [ ] `python kerio_anonymizer.py --help` works
- [ ] `output.txt` was generated
- [ ] `mapping.json` was generated or updated
- [ ] `mapping.json` uses `sha256:` keys
- [ ] repeated runs keep deterministic replacements

## Troubleshooting

### Problem: `Package 'Faker' is required`

**Symptoms**

- the script exits immediately with a `Faker` import error.

**Cause**

- dependencies were not installed in the active environment.

**Solution**

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Problem: input text looks corrupted or unreadable

**Symptoms**

- Cyrillic or other non-ASCII text is garbled in the output;
- names or subjects are read incorrectly.

**Cause**

- the source file uses a non-UTF-8 encoding.

**Solution**

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json --input-encoding cp1251
```

If that still looks wrong, try `cp866`.

### Problem: PowerShell blocks virtual environment activation

**Symptoms**

- `.venv\Scripts\Activate.ps1` is blocked by execution policy.

**Cause**

- local PowerShell policy prevents script execution.

**Solution**

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.venv\Scripts\Activate.ps1
```

### Problem: an old mapping file still contains plain-text keys

**Symptoms**

- you see original values in an older `mapping.json`.

**Cause**

- the mapping file was created before hashed key normalization was added.

**Solution**

```powershell
python kerio_anonymizer.py --input input.txt --output output.txt --mapping mapping.json
```

Expected result:

- on the next save, the script rewrites mapping keys into the `sha256(category:value)` format.

## Limitations / Non-goals

- This is a file-based anonymizer, not a streaming syslog service.
- It currently targets IPv4, not IPv6.
- It uses heuristics for Kerio log formats and may miss uncommon custom fields.
- It is not a full PII discovery engine.
- It does not attempt to preserve every exact linguistic nuance of names or subjects.
- It is not a replacement for vendor documentation or formal data classification procedures.

## Notes

- Deterministic anonymization is intentional. It preserves correlation across repeated events, which is important for dashboards, alert tuning, parser tests, and incident walkthroughs.
- `mapping.json` now stores hashed real keys instead of plain source values, which improves safe sharing, but the file should still be handled carefully because it defines the replacement history for a dataset.
- `127.0.0.1` is preserved and not anonymized.
- Source logs may originate from **Kerio Connect**, which is proprietary vendor software. This repository does not distribute Kerio Connect itself.

## Roadmap

See [NEXT_STEPS.md](./NEXT_STEPS.md)

## Changelog

See [CHANGELOG.md](./CHANGELOG.md)

## Handoff

See [HANDOFF.md](./HANDOFF.md)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

## Security

See [SECURITY.md](./SECURITY.md)

## Support

See [SUPPORT.md](./SUPPORT.md)

## License

See [LICENSE](./LICENSE)
