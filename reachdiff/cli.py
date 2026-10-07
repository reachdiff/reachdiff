"""`reachdiff plan`: who gains or loses Unity Catalog access when a Terraform plan is applied."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from reachdiff.apply import apply_plan
from reachdiff.collect.offline import build_offline
from reachdiff.config import load_config
from reachdiff.diff import compute_diff
from reachdiff.report import RENDERERS, build_report
from reachdiff.rules import evaluate, status_of
from reachdiff.tfplan import read_plan

# Without one of these the SDK tries every login it finds, such as the Terraform deployer's ARM_* secrets.
LOGIN_PINS = ('DATABRICKS_AUTH_TYPE', 'DATABRICKS_CONFIG_PROFILE')
RANK = {'PASS': 0, 'WARN': 1, 'BLOCK': 2}
THRESHOLD = {'warn': 1, 'block': 2, 'never': 3}


def exit_code(status: str, fail_on: str) -> int:
    return RANK[status] if RANK[status] >= THRESHOLD[fail_on] else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='reachdiff', description='Who gains or loses Unity Catalog access when this Terraform plan is applied?'
    )
    commands = parser.add_subparsers(dest='command', required=True)
    plan = commands.add_parser('plan', help='analyze terraform show -json output')
    plan.add_argument('--tfplan', required=True, type=Path, help='output of terraform show -json PLANFILE')
    mode = plan.add_mutually_exclusive_group()
    mode.add_argument('--offline', action='store_true', help='use only data in the plan and report blind spots')
    mode.add_argument('--profile', help='Databricks SDK profile for live, read-only reads')
    plan.add_argument(
        '--deep', action='store_true', help='also read child tables of changed schemas and catalogs (live mode only)'
    )
    plan.add_argument('--config', type=Path, help='reachdiff TOML config')
    plan.add_argument('--format', choices=sorted(RENDERERS), default='text')
    plan.add_argument('--output', type=Path, help='write the report to this file (overwrites) instead of stdout')
    plan.add_argument('--fail-on', choices=sorted(THRESHOLD), help='overrides fail_on from the config')
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse uses 2 for usage errors; 2 means BLOCK here
        return 0 if exc.code == 0 else 3
    if args.offline and args.deep:
        print('reachdiff: error: --deep needs live mode; it cannot be combined with --offline', file=sys.stderr)
        return 3
    if not (args.offline or args.profile or any(os.environ.get(name) for name in LOGIN_PINS)):
        print(
            'reachdiff: error: live mode needs --profile or DATABRICKS_AUTH_TYPE, so a missing credential cannot '
            'fall back to another login',
            file=sys.stderr,
        )
        return 3
    try:
        config = load_config(args.config)
        plan = read_plan(json.loads(args.tfplan.read_text(encoding='utf-8')))
        if args.offline:
            before = build_offline(plan)
        else:
            from reachdiff.collect.live import collect_live

            before = collect_live(plan, config, deep=args.deep, profile=args.profile)
        after = apply_plan(before, plan)
        diff = compute_diff(before, after, plan, members_limit=config.limit_members, deep=args.deep)
        findings = evaluate(diff, plan, before, after, config, deep=args.deep)
        status = status_of(findings)
        output = RENDERERS[args.format](build_report(plan, before, after, diff, findings, status))
        if args.output:
            args.output.write_text(output, encoding='utf-8')
        else:
            sys.stdout.write(output)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f'reachdiff: error: {exc}', file=sys.stderr)
        return 3
    except Exception as exc:  # the message could quote plan values, so only the type is shown
        print(f'reachdiff: error: unexpected {type(exc).__name__}', file=sys.stderr)
        return 3
    return exit_code(status, args.fail_on or config.fail_on)
