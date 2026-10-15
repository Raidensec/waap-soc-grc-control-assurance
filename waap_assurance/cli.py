import argparse
import sys
from pathlib import Path

from .engine import build_alerts, build_cases
from .reporting import write_outputs
from .rules import detect
from .schema import InputFormatError, load_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Triage normalized WAF JSONL and export SOC/GRC case evidence.")
    parser.add_argument("--input", required=True, type=Path, help="Path to normalized WAF JSONL input")
    parser.add_argument("--output", required=True, type=Path, help="Directory for CSV, Markdown, and JSON reports")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        events = load_events(arguments.input)
        alerts = build_alerts(detect(events))
        cases = build_cases(alerts)
        write_outputs(alerts, cases, len(events), arguments.output)
    except (InputFormatError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    print(f"Processed {len(events)} event(s); created {len(alerts)} alert(s) in {len(cases)} case(s).")
    print(f"Reports: {arguments.output.resolve()}")
    return 0
