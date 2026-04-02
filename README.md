# Kerio Syslog Anonymizer

This script anonymizes raw Kerio Connect syslog data stored in `.txt` files.

It replaces sensitive values with deterministic fake ones and stores a persistent mapping so the same source value is always replaced with the same fake value across runs.

## Supported Data Types

- email addresses
- IPv4 addresses
- usernames / logins
- `subject` / `Subject:`
- full names / display names
- domain names

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python kerio_anonymizer.py \
  --input kerio_raw.txt \
  --output kerio_raw_anonymized.txt \
  --mapping mapping.json
```

Example with an explicit input encoding:

```bash
python kerio_anonymizer.py \
  --input kerio_raw.txt \
  --output kerio_raw_anonymized.txt \
  --mapping mapping.json \
  --input-encoding cp1251
```

## Output

- anonymized `.txt` file
- `mapping.json` with `sha256`-hashed real keys mapped to fake values

## Notes

- `127.0.0.1` is preserved as-is and is not anonymized
- the script uses heuristics for common Kerio syslog fields
- if your logs contain custom field formats, extra patterns can be added easily
