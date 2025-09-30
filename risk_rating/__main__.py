from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import RiskRatingEvaluator, load_rules


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Determine vendor risk rating from analyst notes.")
    parser.add_argument("notes", help="Path to a text file containing analyst notes or raw text.")
    parser.add_argument(
        "--rules",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "rules" / "rating_rules.json",
        help="Path to the rating rules JSON file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the evaluation result as JSON.",
    )
    return parser.parse_args()


def load_notes(notes_arg: str) -> str:
    path = Path(notes_arg)
    if path.exists():
        return path.read_text(encoding="utf-8")
    return notes_arg


def main() -> None:
    args = parse_args()
    notes = load_notes(args.notes)
    rules_path = args.rules
    if not rules_path.exists():
        default_rules = Path(__file__).resolve().parent.parent / "rules" / "rating_rules.json"
        rules_path = default_rules
    rules = load_rules(rules_path)
    evaluator = RiskRatingEvaluator(rules)
    result = evaluator.evaluate(notes)
    output = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
