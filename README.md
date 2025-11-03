# CSV De-identification Script

De-identifies specific columns in a CSV file using hashing, masking, redaction, or random numeric replacement. Designed to be simple, fast, and suitable for large files by streaming rows.

- No external dependencies (Python standard library only)
- Global method or per-column rules
- Deterministic hashing with optional salt
- Flexible masking with visible prefix
- Redaction with custom placeholder
- Random numeric replacement with fixed digit width

## Requirements
- Python 3.8+ (tested with Python 3.9)

## Files in this project
- `csv_de_identification_script.py` — the CLI script

## Quick start
```bash
python3 csv_de_identification_script.py INPUT.csv OUTPUT.csv --columns email ssn --method redact
```

## Usage
```bash
python3 csv_de_identification_script.py INPUT.csv OUTPUT.csv \
  [--columns COL1 COL2 ...] \
  [--method {hash,mask,redact,random}] \
  [--salt SALT] \
  [--mask-char CH] \
  [--visible N] \
  [--redaction-text TEXT] \
  [--column-rule "column=method[:key=value,...]"] ... \
  [--random-digits N]
```

### Options
- `--columns`, `-c` (space-separated)
  - Column names to de-identify. Optional if you supply one or more `--column-rule` entries. If both are supplied, the effective set is the union of all names.
- `--method`, `-m` (default: `hash`)
  - Global/default method for columns without an explicit per-column rule. One of: `hash`, `mask`, `redact`, `random`.
- `--salt`, `-s`
  - Salt for the `hash` method. The script computes `sha256(value + salt)` and truncates to 16 hex characters.
- `--mask-char` (default: `*`)
  - Masking character used by the `mask` method.
- `--visible` (default: `0`)
  - Number of leading characters to keep visible when masking. The remainder is replaced by `mask_char`.
- `--redaction-text` (default: `[REDACTED]`)
  - Replacement text used by the `redact` method.
- `--column-rule` (repeatable)
  - Per-column rule in the form `column=method[:key=value,...]`. You may repeat this flag for multiple columns. See examples below.
- `--random-digits` (default: `8`)
  - Default number of digits for the `random` method when used globally (or when a rule omits `digits`). Values are zero-padded to fixed width.

### Per-column rule syntax
Each `--column-rule` accepts these forms:
- `column=method`
- `column=method:key=value`
- `column=method:key=value,other=val`

Supported keys by method:
- `hash`: `salt`
- `mask`: `visible` (or `visible_chars`), `mask_char`
- `redact`: `redaction_text`
- `random`: `digits`

Examples:
```bash
--column-rule name=redact
--column-rule phone=mask:visible=3,mask_char=x
--column-rule email=hash:salt=pepper
--column-rule case_id=random:digits=10
```

## Examples
- Hash email and SSN columns using a global method:
```bash
python3 csv_de_identification_script.py input.csv output.csv --columns email ssn
```

- Mask phone numbers, showing the first 3 digits (global mask):
```bash
python3 csv_de_identification_script.py input.csv output.csv --columns phone --method mask --visible 3
```

- Redact sensitive columns (global redact):
```bash
python3 csv_de_identification_script.py input.csv output.csv --columns name address --method redact
```

- Hash with a custom salt (global):
```bash
python3 csv_de_identification_script.py input.csv output.csv --columns email --method hash --salt "my_secret"
```

- Per-column rules (different methods per column):
```bash
python3 csv_de_identification_script.py input.csv output.csv \
  --column-rule name=redact \
  --column-rule phone=mask:visible=3,mask_char=x \
  --column-rule email=hash:salt=pepper \
  --column-rule case_id=random:digits=10
```

- Mix of global and per-column: default mask, but hash email with salt:
```bash
python3 csv_de_identification_script.py input.csv output.csv --columns name address --method mask --visible 2 \
  --column-rule email=hash:salt=pepper
```

## Behavior and notes
- CSV handling
  - The script streams the CSV: it reads a row, transforms specified columns, and writes immediately. Suitable for large files.
  - Header line is written without quotes. Data rows are written with all values quoted.
  - Input and output encoding is UTF-8.
- Column validation
  - If any requested column is missing from the CSV header, the script stops with an error listing the missing names.
- Methods
  - `hash`: `sha256(value + salt)`, 16 hex chars (deterministic). Do not rely on this as cryptographic anonymization for re-identification-risk-free datasets; evaluate your privacy requirements.
  - `mask`: Shows the first `visible` characters and replaces the remainder with `mask_char`.
  - `redact`: Replaces any non-empty value with `redaction_text`.
  - `random`: Replaces with a random numeric string of fixed width (`digits`), zero-padded. Each value is replaced independently and non-deterministically.
- Performance
  - Avoids loading the entire file into memory. Expect near line-rate performance for typical CSVs.

## Troubleshooting
- "Columns not found in CSV": Check spelling and case of column names; they must match header values exactly.
- Empty or missing headers: The script requires a header row; ensure your CSV is well-formed.
- Encoding issues: Ensure files are UTF-8. If your data uses another encoding, convert it prior to running the script.

## Security and privacy considerations
- Hashing with a static salt reduces but does not eliminate re-identification risk. Consider stronger transformations or tokenization if linkage attacks are a concern.
- Random replacement is not reversible; keep your original data secure and separate from outputs.
