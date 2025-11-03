#!/usr/bin/env python3
"""
CSV De-identification Script

De-identifies specific columns in a CSV file using various methods.
"""

import csv
import hashlib
import argparse
from pathlib import Path
from typing import List, Callable


def hash_value(value: str, salt: str = "") -> str:
    """Hash a value using SHA-256."""
    return hashlib.sha256(f"{value}{salt}".encode()).hexdigest()[:16]


def mask_value(value: str, mask_char: str = "*", visible_chars: int = 0) -> str:
    """Mask a value, optionally showing first N characters."""
    if not value:
        return value
    if visible_chars > 0:
        return value[:visible_chars] + mask_char * max(0, len(value) - visible_chars)
    return mask_char * len(value)


def redact_value(value: str, replacement: str = "[REDACTED]") -> str:
    """Replace value with a redaction placeholder."""
    return replacement if value else value


def deidentify_csv(
        input_file: str,
        output_file: str,
        columns_to_deidentify: List[str],
        method: str = "hash",
        salt: str = "",
        mask_char: str = "*",
        visible_chars: int = 0,
        redaction_text: str = "[REDACTED]"
) -> None:
    """
    De-identify specific columns in a CSV file.

    Args:
        input_file: Path to input CSV file
        output_file: Path to output CSV file
        columns_to_deidentify: List of column names to de-identify
        method: De-identification method ('hash', 'mask', or 'redact')
        salt: Salt for hashing (optional)
        mask_char: Character to use for masking
        visible_chars: Number of characters to leave visible when masking
        redaction_text: Text to use for redaction
    """

    # Choose de-identification function based on method
    deidentify_func: Callable[[str], str]

    if method == "hash":
        deidentify_func = lambda x: hash_value(x, salt)
    elif method == "mask":
        deidentify_func = lambda x: mask_value(x, mask_char, visible_chars)
    elif method == "redact":
        deidentify_func = lambda x: redact_value(x, redaction_text)
    else:
        raise ValueError(f"Unknown method: {method}. Use 'hash', 'mask', or 'redact'.")

    # Read input CSV and write de-identified output (streaming, optimized for large files)
    with open(input_file, 'r', newline='', encoding='utf-8') as infile, \
            open(output_file, 'w', newline='', encoding='utf-8') as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        # Read header
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("CSV file appears to be empty or missing headers")

        # Map column names to indexes
        name_to_index = {name: idx for idx, name in enumerate(header)}
        missing_columns = set(columns_to_deidentify) - set(name_to_index)
        if missing_columns:
            raise ValueError(f"Columns not found in CSV: {missing_columns}")

        # Prepare list of target indexes and write header
        target_indexes = [name_to_index[c] for c in columns_to_deidentify]
        writer.writerow(header)

        # Prebind for speed in the hot loop
        _deidentify = deidentify_func
        _len_header = len(header)

        rows_processed = 0
        for row in reader:
            # Ensure row has consistent length with header (pad or trim)
            if len(row) < _len_header:
                row.extend([''] * (_len_header - len(row)))
            elif len(row) > _len_header:
                row = row[:_len_header]

            # De-identify specified columns by index
            for idx in target_indexes:
                val = row[idx]
                if val:
                    row[idx] = _deidentify(val)

            writer.writerow(row)
            rows_processed += 1

    print(f"✓ Successfully de-identified {rows_processed} rows")
    print(f"✓ De-identified columns: {', '.join(columns_to_deidentify)}")
    print(f"✓ Method used: {method}")
    print(f"✓ Output saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="De-identify specific columns in a CSV file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Hash email and ssn columns
  python deidentify_csv.py input.csv output.csv --columns email ssn

  # Mask phone numbers, showing first 3 digits
  python deidentify_csv.py input.csv output.csv --columns phone --method mask --visible 3

  # Redact sensitive columns
  python deidentify_csv.py input.csv output.csv --columns name address --method redact

  # Hash with custom salt
  python deidentify_csv.py input.csv output.csv --columns email --method hash --salt "my_secret"
        """
    )

    parser.add_argument("input_file", help="Path to input CSV file")
    parser.add_argument("output_file", help="Path to output CSV file")
    parser.add_argument(
        "--columns", "-c",
        nargs="+",
        required=True,
        help="Column names to de-identify (space-separated)"
    )
    parser.add_argument(
        "--method", "-m",
        choices=["hash", "mask", "redact"],
        default="hash",
        help="De-identification method (default: hash)"
    )
    parser.add_argument(
        "--salt", "-s",
        default="",
        help="Salt for hashing method"
    )
    parser.add_argument(
        "--mask-char",
        default="*",
        help="Character to use for masking (default: *)"
    )
    parser.add_argument(
        "--visible",
        type=int,
        default=0,
        help="Number of characters to leave visible when masking (default: 0)"
    )
    parser.add_argument(
        "--redaction-text",
        default="[REDACTED]",
        help="Text to use for redaction (default: [REDACTED])"
    )

    args = parser.parse_args()

    try:
        deidentify_csv(
            input_file=args.input_file,
            output_file=args.output_file,
            columns_to_deidentify=args.columns,
            method=args.method,
            salt=args.salt,
            mask_char=args.mask_char,
            visible_chars=args.visible,
            redaction_text=args.redaction_text
        )
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())