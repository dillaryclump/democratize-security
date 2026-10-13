"""Offline validation and planning only; no model, database or worker access."""

import argparse
import json
import sys
from pathlib import Path

from democratize_security import __version__
from democratize_security.contracts import ContractError, load_campaign, plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "plan"):
        command = commands.add_parser(name)
        command.add_argument("campaign", type=Path)
    args = parser.parse_args(argv)
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
