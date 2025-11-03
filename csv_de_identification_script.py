#!/usr/bin/env python3
"""
CSV De-identification Script

De-identifies specific columns in a CSV file using various methods.
"""

import csv
import hashlib
import argparse
import random
from typing import List, Callable, Dict, Optional


def parse_column_rule_items(items: Optional[List[str]]) -> Optional[Dict[str, Dict[str, str]]]:
    """
    Parse --column-rule entries.

    Accepted formats per item:
      - column=method
      - column=method:key=value
      - column=method:key=value,other=val
    Examples:
      name=redact
      phone=mask:visible=3,mask_char=x
      email=hash:salt=pepper
      id=random:digits=10
    """
    if not items:
        return None
    rules: Dict[str, Dict[str, str]] = {}
    for raw in items:
        if '=' not in raw:
            raise ValueError(f"Invalid --column-rule '{raw}'. Expected 'column=method[:key=value,...]'")
        column, rest = raw.split('=', 1)
        if not column:
            raise ValueError(f"Invalid --column-rule '{raw}': empty column name")
        # method and optional params after ':'
        if ':' in rest:
            method_part, params_part = rest.split(':', 1)
        else:
            method_part, params_part = rest, ''
        method = method_part.strip()
        rule: Dict[str, str] = {"method": method}
        if params_part:
            # comma-separated key=value
            for kv in params_part.split(','):
                kv = kv.strip()
                if not kv:
                    continue
                if '=' not in kv:
                    raise ValueError(f"Invalid param '{kv}' in --column-rule '{raw}'. Expected key=value")
                k, v = kv.split('=', 1)
                rule[k.strip()] = v.strip()
        rules[column.strip()] = rule
    return rules


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


def random_numeric(value: str, digits: int = 8) -> str:
    """Generate a random numeric string with the specified number of digits (default 8)."""
    # Keep width with leading zeros if needed
    if digits <= 0:
        digits = 8
    return str(random.randint(0, 10**digits - 1)).zfill(digits)


def deidentify_csv(
        input_file: str,
        output_file: str,
        columns_to_deidentify: List[str],
        method: str = "hash",
        salt: str = "",
        mask_char: str = "*",
        visible_chars: int = 0,
        redaction_text: str = "[REDACTED]",
        column_rules: Optional[Dict[str, Dict[str, str]]] = None,
        random_digits: int = 8,
) -> None:
    """
    De-identify specific columns in a CSV file.

    Args:
        input_file: Path to input CSV file
        output_file: Path to output CSV file
        columns_to_deidentify: List of column names to de-identify
        method: Default/global de-identification method ('hash', 'mask', 'redact', or 'random')
        salt: Salt for hashing (optional)
        mask_char: Character to use for masking
        visible_chars: Number of characters to leave visible when masking
        redaction_text: Text to use for redaction
        column_rules: Optional mapping of column name -> rule dict with keys like 'method', 'salt', 'mask_char', 'visible', 'redaction_text', 'digits'
        random_digits: Default number of digits for the random generator when used globally (default 8)
    """

    # Helper to build a function from a rule dict
    def build_func_from_rule(rule: Dict[str, str]) -> Callable[[str], str]:
        m = rule.get("method", method)
        if m == "hash":
            return lambda x: hash_value(x, rule.get("salt", salt))
        elif m == "mask":
            mc = rule.get("mask_char", mask_char)
            vis = int(rule.get("visible", rule.get("visible_chars", str(visible_chars))))
            return lambda x: mask_value(x, mc, vis)
        elif m == "redact":
            txt = rule.get("redaction_text", redaction_text)
            return lambda x: redact_value(x, txt)
        elif m == "random":
            digits = int(rule.get("digits", str(random_digits if random_digits > 0 else 8)))
            return lambda x: random_numeric(x, digits)
        else:
            raise ValueError(f"Unknown method: {m}. Use 'hash', 'mask', 'redact', or 'random'.")

    # Build global/default function
    global_rule = {"method": method, "salt": salt, "mask_char": mask_char, "visible_chars": str(visible_chars), "redaction_text": redaction_text, "digits": str(random_digits)}
    default_func = build_func_from_rule(global_rule)

    # Read input CSV and write de-identified output (streaming, optimized for large files)
    with open(input_file, 'r', newline='', encoding='utf-8') as infile, \
            open(output_file, 'w', newline='', encoding='utf-8') as outfile:

        reader = csv.reader(infile)
        # Writers: header without quotes; data values fully quoted
        writer_header = csv.writer(
            outfile,
            quoting=csv.QUOTE_NONE,
            escapechar='\\',
            quotechar='"'
        )
        writer = csv.writer(outfile, quoting=csv.QUOTE_ALL, quotechar='"')

        # Read header
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("CSV file appears to be empty or missing headers")

        # Map column names to indexes
        name_to_index = {name: idx for idx, name in enumerate(header)}

        # Validate requested columns
        requested_columns = set(columns_to_deidentify)
        if column_rules:
            requested_columns |= set(column_rules.keys())
        missing_columns = requested_columns - set(name_to_index)
        if missing_columns:
            raise ValueError(f"Columns not found in CSV: {missing_columns}")

        # Write header without double quotes
        writer_header.writerow(header)

        # Build per-index function map
        col_funcs: Dict[int, Callable[[str], str]] = {}
        if column_rules:
            for col, rule in column_rules.items():
                if col in name_to_index:
                    col_funcs[name_to_index[col]] = build_func_from_rule(rule)

        # For any remaining columns in columns_to_deidentify without explicit rule, use default
        for col in columns_to_deidentify:
            idx = name_to_index[col]
            if idx not in col_funcs:
                col_funcs[idx] = default_func

        # Prebind for speed in the hot loop
        _len_header = len(header)

        rows_processed = 0
        for row in reader:
            # Ensure row has consistent length with header (pad or trim)
            if len(row) < _len_header:
                row.extend([''] * (_len_header - len(row)))
            elif len(row) > _len_header:
                row = row[:_len_header]

            # De-identify specified columns using their mapped functions
            for idx, func in col_funcs.items():
                val = row[idx]
                if val:
                    row[idx] = func(val)

            writer.writerow(row)
            rows_processed += 1

    # Build reporting strings
    all_cols = [c for c in header if name_to_index.get(c) in col_funcs] if 'header' in locals() else columns_to_deidentify
    print(f"✓ Successfully de-identified {rows_processed} rows")
    print(f"✓ De-identified columns: {', '.join(sorted(requested_columns))}")
    used_methods = set([method])
    if column_rules:
        for r in column_rules.values():
            if 'method' in r:
                used_methods.add(r['method'])
    print(f"✓ Methods used: {', '.join(sorted(used_methods))}")
    print(f"✓ Output saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="De-identify specific columns in a CSV file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Hash email and ssn columns (global method)
  python deidentify_csv.py input.csv output.csv --columns email ssn

  # Mask phone numbers, showing first 3 digits (global mask)
  python deidentify_csv.py input.csv output.csv --columns phone --method mask --visible 3

  # Redact sensitive columns (global redact)
  python deidentify_csv.py input.csv output.csv --columns name address --method redact

  # Hash with custom salt (global)
  python deidentify_csv.py input.csv output.csv --columns email --method hash --salt "my_secret"

  # Per-column rules: different methods per column
  python deidentify_csv.py input.csv output.csv \
    --column-rule name=redact \
    --column-rule phone=mask:visible=3,mask_char=x \
    --column-rule email=hash:salt=pepper \
    --column-rule case_id=random:digits=10

  # Mix of global and per-column: default mask, but hash email with salt
  python deidentify_csv.py input.csv output.csv --columns name address --method mask --visible 2 \
    --column-rule email=hash:salt=pepper
        """
    )

    parser.add_argument("input_file", help="Path to input CSV file")
    parser.add_argument("output_file", help="Path to output CSV file")
    parser.add_argument(
        "--columns", "-c",
        nargs="+",
        required=False,
        help="Column names to de-identify (space-separated). Optional if --column-rule is provided."
    )
    parser.add_argument(
        "--method", "-m",
        choices=["hash", "mask", "redact", "random"],
        default="hash",
        help="Default de-identification method for columns without explicit rule (default: hash)"
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
    parser.add_argument(
        "--column-rule",
        dest="column_rule",
        action="append",
        help=(
            "Per-column rule in the form column=method[:key=value,...]. "
            "Examples: name=redact, phone=mask:visible=3,mask_char=x, "
            "email=hash:salt=pepper, case_id=random:digits=10. "
            "Repeat this option for multiple columns."
        )
    )
    parser.add_argument(
        "--random-digits",
        type=int,
        default=8,
        help="Default number of digits for the random method (when used globally or when not specified per-column). Default: 8"
    )

    args = parser.parse_args()

    try:
        # Parse per-column rules
        column_rules = parse_column_rule_items(args.column_rule)

        # Determine effective columns
        columns = args.columns or []
        if column_rules:
            # union of provided columns and rule keys
            rule_cols = list(column_rules.keys())
            for c in rule_cols:
                if c not in columns:
                    columns.append(c)
        if not columns:
            raise ValueError("No columns specified. Provide --columns and/or at least one --column-rule.")

        deidentify_csv(
            input_file=args.input_file,
            output_file=args.output_file,
            columns_to_deidentify=columns,
            method=args.method,
            salt=args.salt,
            mask_char=args.mask_char,
            visible_chars=args.visible,
            redaction_text=args.redaction_text,
            column_rules=column_rules,
            random_digits=args.random_digits,
        )
    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())