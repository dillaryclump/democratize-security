"""Offline campaign planning and artifact sealing/inspection; no workload execution."""

import argparse
import json
import sys
from pathlib import Path

from democratize_security import __version__, artifacts
from democratize_security.contracts import ContractError, load_campaign, plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "plan"):
        command = commands.add_parser(name)
        command.add_argument("campaign", type=Path)
    command = commands.add_parser("seal", help="Seal explicitly allowed files; executes no code")
    command.add_argument("root", type=Path)
    command.add_argument("--file", action="append", required=True, dest="files")
    command.add_argument("--output", type=Path, required=True)
    command = commands.add_parser("inspect-artifact", help="Check bundle integrity and limits")
    command.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    if args.command in {"seal", "inspect-artifact"}:
        try:
            if args.command == "seal":
                bundle = artifacts.seal(args.root, args.files)
                artifacts.write_new(bundle, args.output)
            else:
                bundle = artifacts.load(args.bundle)
            print(json.dumps(artifacts.validate(bundle), indent=2))
            return 0
        except (OSError, ValueError, RecursionError) as error:
            print(f"Invalid artifact: {error}", file=sys.stderr)
            return 2
    try:
        campaign = load_campaign(args.campaign)
        result = plan(campaign)
    except (ContractError, OSError, ValueError, RecursionError) as error:
        print(f"Invalid campaign: {error}", file=sys.stderr)
        return 2
    if args.command == "validate":
        result = {
            "valid": True,
            "campaign_id": result["campaign_id"],
            "trial_count": len(result["trials"]),
            "execution_enabled": False,
        }
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
