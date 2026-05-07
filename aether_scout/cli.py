from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .config import settings_from_env
from .discovery import discover_assets_with_audit
from .link_client import LinkClient
from .request_shapes import import_request_shapes
from .scope_loader import load_scope_file, scope_from_link_current
from .surface_mapper import map_surfaces


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aether-scout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run")
    run.add_argument("--scope", help="Local scope.toml path.")
    run.add_argument("--link-url", help="Aether-Link base URL.")
    run.add_argument("--out", help="JSONL output path.")
    run.add_argument("--audit-log", help="JSONL path for rejected candidates.")
    run.add_argument("--passive-only", action="store_true")

    validate = sub.add_parser("validate-scope")
    validate.add_argument("--scope", required=True)

    push = sub.add_parser("push-assets")
    push.add_argument("--assets", required=True)
    push.add_argument("--link-url", required=True)

    map_cmd = sub.add_parser("map-surfaces")
    map_cmd.add_argument("--scope", required=True)
    map_cmd.add_argument("--out", required=True)
    map_cmd.add_argument("--audit-log")
    map_cmd.add_argument("--passive-only", action="store_true")

    push_surfaces = sub.add_parser("push-surfaces")
    push_surfaces.add_argument("--surfaces", required=True)
    push_surfaces.add_argument("--link-url", required=True)

    import_shapes = sub.add_parser("import-request-shapes")
    import_shapes.add_argument("--input", required=True)
    import_shapes.add_argument("--scope", required=True)
    import_shapes.add_argument("--out", required=True)
    import_shapes.add_argument("--audit-log")

    push_schemas = sub.add_parser("push-schemas")
    push_schemas.add_argument("--schemas", required=True)
    push_schemas.add_argument("--link-url", required=True)
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
            client = LinkClient(args.link_url, settings.api_token, timeout=settings.timeout_seconds, batch_size=settings.link_batch_size)
            assets = _read_jsonl(args.assets)
            responses = client.post_assets(assets)
            print(f"posted={len(responses)} link_url={args.link_url}")
            return 0
        if args.command == "push-surfaces":
            client = LinkClient(args.link_url, settings.api_token, timeout=settings.timeout_seconds, batch_size=settings.link_batch_size)
            surfaces = _read_jsonl(args.surfaces)
            responses = client.post_surfaces(surfaces)
            print(f"posted={len(responses)} link_url={args.link_url}")
            return 0
        if args.command == "push-schemas":
            client = LinkClient(args.link_url, settings.api_token, timeout=settings.timeout_seconds, batch_size=settings.link_batch_size)
            schemas = _read_jsonl(args.schemas)
            responses = client.post_schemas(schemas)
            print(f"posted={len(responses)} link_url={args.link_url}")
            return 0
        if args.command == "import-request-shapes":
            return _import_request_shapes(args)
        if args.command == "map-surfaces":
            return _map_surfaces(args, settings)
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
        client = LinkClient(link_url, settings.api_token, timeout=settings.timeout_seconds, batch_size=settings.link_batch_size)
        client.health()
        scope = scope_from_link_current(client.current_config())
        scope.validate_for_run()
    else:
        raise ValueError("scope or link-url required")

    assets, logs, rejected = discover_assets_with_audit(scope, settings)
    _write_jsonl(out_path, [asset.to_dict() for asset in assets])
    if args.audit_log:
        _write_jsonl(Path(args.audit_log), [record.to_dict() for record in rejected])

    posted = 0
    if link_url:
        client = LinkClient(link_url, settings.api_token, timeout=settings.timeout_seconds, batch_size=settings.link_batch_size)
        client.post_assets([asset.to_dict() for asset in assets])
        posted = len(assets)
    for line in logs:
        print(f"log={line}", file=sys.stderr)
    print(f"program_id={scope.program_id} assets={len(assets)} rejected={len(rejected)} out={out_path} posted={posted}")
    return 0


def _map_surfaces(args: argparse.Namespace, settings) -> int:
    settings.passive_only = bool(args.passive_only or settings.passive_only)
    scope = load_scope_file(args.scope)
    surfaces, logs, rejected = map_surfaces(scope, settings)
    out_path = Path(args.out)
    _write_jsonl(out_path, [surface.to_dict() for surface in surfaces])
    if args.audit_log:
        _write_jsonl(Path(args.audit_log), [record.to_dict() for record in rejected])
    for line in logs:
        print(f"log={line}", file=sys.stderr)
    print(f"program_id={scope.program_id} surfaces={len(surfaces)} rejected={len(rejected)} out={out_path}")
    return 0


def _import_request_shapes(args: argparse.Namespace) -> int:
    scope = load_scope_file(args.scope)
    records = json.loads(Path(args.input).read_text(encoding="utf-8"))
    schemas, rejected = import_request_shapes(records, scope)
    out_path = Path(args.out)
    _write_jsonl(out_path, [schema.to_dict() for schema in schemas])
    if args.audit_log:
        _write_jsonl(Path(args.audit_log), [record.to_dict() for record in rejected])
    print(f"program_id={scope.program_id} schemas={len(schemas)} rejected={len(rejected)} out={out_path}")
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
