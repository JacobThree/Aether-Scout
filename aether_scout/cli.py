from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .config import settings_from_env
from .discovery import discover_assets
from .link_client import LinkClient
from .scope_loader import load_scope_file, scope_from_link_current


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aether-scout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run")
    run.add_argument("--scope", help="Local scope.toml path.")
    run.add_argument("--link-url", help="Aether-Link base URL.")
    run.add_argument("--out", help="JSONL output path.")
    run.add_argument("--passive-only", action="store_true")

    validate = sub.add_parser("validate-scope")
    validate.add_argument("--scope", required=True)

    push = sub.add_parser("push-assets")
    push.add_argument("--assets", required=True)
    push.add_argument("--link-url", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = settings_from_env()

    try:
        if args.command == "validate-scope":
            scope = load_scope_file(args.scope)
            print(f"valid program_id={scope.program_id} include_rules={len(scope.include_rules())}")
            return 0
        if args.command == "push-assets":
            client = LinkClient(args.link_url, settings.api_token, timeout=settings.timeout_seconds)
            assets = _read_jsonl(args.assets)
            responses = client.post_assets(assets)
            print(f"posted={len(responses)} link_url={args.link_url}")
            return 0
        if args.command == "run":
            return _run(args, settings)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


def _run(args: argparse.Namespace, settings) -> int:
    settings.passive_only = bool(args.passive_only or settings.passive_only)
    link_url = args.link_url or settings.link_url
    out_path = Path(args.out or settings.output_file)
    if args.scope or settings.scope_file:
        scope = load_scope_file(args.scope or settings.scope_file)
    elif link_url:
        client = LinkClient(link_url, settings.api_token, timeout=settings.timeout_seconds)
        client.health()
        scope = scope_from_link_current(client.current_config())
        scope.validate_for_run()
    else:
        raise ValueError("scope or link-url required")

    assets, logs = discover_assets(scope, settings)
    _write_jsonl(out_path, [asset.to_dict() for asset in assets])

    posted = 0
    if link_url:
        client = LinkClient(link_url, settings.api_token, timeout=settings.timeout_seconds)
        client.post_assets([asset.to_dict() for asset in assets])
        posted = len(assets)
    for line in logs:
        print(f"log={line}", file=sys.stderr)
    print(f"program_id={scope.program_id} assets={len(assets)} out={out_path} posted={posted}")
    return 0


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def _read_jsonl(path: str) -> list[dict]:
    rows: list[dict] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows
