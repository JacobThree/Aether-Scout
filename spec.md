# Spec: Aether-Scout

## Assumptions
1. Aether-Scout is a Python 3.11+ CLI/service package.
2. Aether-Link owns final policy decisions for scope and asset handling.
3. Aether-Scout performs conservative discovery only, not exploit testing.
4. Local development can run without external recon binaries, using fallbacks where available.
5. Optional tools such as `subfinder`, `httpx`, and `dnsx` are wrappers, not hard runtime dependencies.

## Objective
Aether-Scout is the recon/discovery engine for the Aether bug bounty automation stack. It loads approved scope, discovers candidate assets and surfaces, deduplicates results, assigns confidence, writes JSONL, and can post discovered assets to Aether-Link.

Primary users are automation operators and Aether-Link. Success means Aether-Scout reliably finds in-scope assets while staying conservative when scope is ambiguous.

Acceptance criteria:
- Refuses to run without explicit scope.
- Refuses scope where `default_decision` is not `deny`.
- Discovers only against approved include patterns.
- Produces asset records with enough metadata for human review.
- Posts discovered assets to Aether-Link instead of sending work to Aether-Probe.
- Never generates payloads, runs exploit tests, or performs destructive testing.

## Tech Stack
- Language: Python `>=3.11`
- Package: `aether-scout`
- Import package: `aether_scout`
- CLI: `aether-scout`
- Build backend: `setuptools>=68`
- Runtime dependencies: standard library by default
- Optional external binaries: `subfinder`, `httpx`, `dnsx`
- Test framework: `unittest`

## Commands
Install editable:

```bash
python -m pip install -e .
```

Run with local scope:

```bash
aether-scout run --scope ./examples/scope.toml --out ./assets.jsonl --audit-log ./rejected.jsonl
```

Run with Aether-Link:

```bash
aether-scout run --link-url http://localhost:8080
```

Validate scope:

```bash
aether-scout validate-scope --scope ./examples/scope.toml
```

Push assets:

```bash
aether-scout push-assets --assets ./assets.jsonl --link-url http://localhost:8080
```

Run tests:

```bash
python -m unittest discover -s tests
```

Build package:

```bash
python -m build
```

## Project Structure
```text
README.md                         Project overview and CLI examples
spec.md                           Living product/engineering specification
pyproject.toml                    Python package metadata
Dockerfile                        Container build definition
docker-compose.example.yml        Example local service wiring
context.md                        Generation context and architecture notes
examples/scope.toml               Example approved scope file
tests/                            Unit tests
aether_scout/__main__.py          Module entrypoint
aether_scout/cli.py               CLI parser and command handlers
aether_scout/config.py            Environment settings
aether_scout/link_client.py       Aether-Link HTTP client
aether_scout/scope_loader.py      Local/link scope loading
aether_scout/discovery.py         Discovery orchestration
aether_scout/dedupe.py            Asset deduplication
aether_scout/asset_builder.py     Asset record construction
aether_scout/models/scope.py      Scope models and validation
aether_scout/models/asset.py      Asset model
aether_scout/tools/               Conservative discovery tool wrappers
```

## Code Style
Use typed, small functions with explicit validation before network or discovery behavior. Prefer standard library APIs. Keep external tool wrappers isolated under `aether_scout/tools/`.

Example:

```python
from pathlib import Path

from aether_scout.scope_loader import load_scope_file


def validate_scope_path(path: str) -> int:
    scope = load_scope_file(Path(path))
    scope.validate_for_run()
    print(f"valid program_id={scope.program_id} include_rules={len(scope.include_rules())}")
    return 0
```

Conventions:
- Package/module names use `snake_case`.
- CLI command and Docker service names use `aether-scout`.
- Environment variables use `AETHER_SCOUT_` or shared `AETHER_` prefixes.
- Discovery modules return structured data plus logs; they do not print directly unless in CLI boundary.
- Errors should fail closed when scope or policy is unclear.

## Testing Strategy
Use `unittest` under `tests/`.

Coverage targets:
- Scope parsing, normalization, include/exclude decisions, wildcard handling, and default-deny enforcement.
- JSONL read/write behavior for asset files.
- Asset dedupe keys and confidence preservation.
- Link client request shape for `GET /health`, `GET /configs/current`, and `POST /assets`.
- Discovery wrappers with mocked command output and no real network dependency in unit tests.

Verification levels:
- Unit tests for models, parsers, and wrappers.
- CLI smoke tests for `validate-scope`, `run --scope`, and `push-assets` with local fixtures.
- Manual integration test against local Aether-Link only after unit tests pass.

## Boundaries
Always:
- Load scope from Aether-Link or local `scope.toml`.
- Require `default_decision = "deny"`.
- Require at least one include rule before running.
- Restrict discovery to approved root domains and URL prefixes.
- Deduplicate assets before output or submission.
- Mark uncertain discoveries with lower confidence.
- Preserve metadata explaining discovery method and source.
- Post assets to Aether-Link for final policy handling.

Ask first:
- Adding runtime dependencies.
- Changing scope schema.
- Changing Aether-Link API contracts.
- Enabling deeper crawling.
- Increasing request rate or concurrency defaults.
- Adding new external recon tools.
- Changing Docker networking or service names.

Never:
- Run without scope.
- Run against out-of-scope patterns.
- Deep crawl by default.
- Fuzz paths by default.
- Run vulnerability templates by default.
- Generate payloads.
- Execute exploit tests.
- Create Aether-Probe jobs directly.
- Classify final vulnerabilities.
- Auto-submit reports.
- Perform DoS, spam, credential stuffing, persistence, malware, or data exfiltration behavior.
- Commit secrets or real API tokens.

## External Interfaces
Aether-Link endpoints:

```text
GET /health
GET /configs/current
POST /assets
```

Recommended environment variables:

```text
AETHER_LINK_URL=http://aether-link:8080
AETHER_API_TOKEN=change_me
AETHER_SCOUT_WORKER_ID=scout_local_001
AETHER_SCOUT_SCOPE_FILE=/shared/configs/current/scope.toml
AETHER_SCOUT_OUTPUT_FILE=/shared/assets/assets.jsonl
AETHER_SCOUT_PASSIVE_ONLY=false
AETHER_SCOUT_MAX_CONCURRENT_PROBES=5
AETHER_SCOUT_REQUESTS_PER_MINUTE=30
AETHER_SCOUT_TIMEOUT_SECONDS=10
AETHER_SCOUT_LINK_BATCH_SIZE=50
AETHER_SCOUT_USER_AGENT=Aether-Scout authorized-recon
```

## Asset Schema
Expected JSON asset shape:

```json
{
  "program_id": "program_example_001",
  "url": "https://api.example.com/mcp",
  "host": "api.example.com",
  "ip": "203.0.113.10",
  "port": 443,
  "scheme": "https",
  "status_code": 200,
  "title": "Example API",
  "technologies": ["cloudflare", "fastapi"],
  "interesting_paths": ["/mcp", "/openapi.json"],
  "discovered_by": "aether-scout",
  "discovery_methods": ["subfinder", "httpx", "mcp_detector"],
  "confidence": 0.82,
  "metadata": {
    "redirects_to": null,
    "content_type": "application/json"
  }
}
```

## Discovery Scope
Modules:
- `scope_loader`: load and validate local or Aether-Link scope.
- `passive_discovery`: optional passive sources, conservative and configurable.
- `subdomain_discovery`: use `subfinder` when available, only for approved root domains.
- `dns_probe`: resolve domains with `dnsx` or fallback resolver.
- `http_probe`: find live services and capture status, title, server, content type, redirects, and TLS info.
- `robots_sitemap`: inspect `robots.txt` and `sitemap.xml` without deep crawling.
- `mcp_detector`: detect likely AI/MCP surfaces such as `/mcp`, `/api/mcp`, `/tools`, `/openapi.json`, `/swagger.json`, `/.well-known/openapi.json`, and `/.well-known/ai-plugin.json`.
- `tech_fingerprint`: record visible technology hints without vulnerability claims.

CIDR scope rules are validation-only for MVP. They validate resolved IPs for discovered hostnames and must not trigger CIDR enumeration or active IP block scanning.

Primary asset output contains accepted assets only. Rejected candidates belong in an explicit audit JSONL file created with `--audit-log`.

Active polling modules must use request throttling from `AETHER_SCOUT_REQUESTS_PER_MINUTE`. Aether-Link asset submission uses chunked batches controlled by `AETHER_SCOUT_LINK_BATCH_SIZE`.

## Success Criteria
- `python -m unittest discover -s tests` passes.
- `aether-scout validate-scope --scope ./examples/scope.toml` exits `0`.
- `aether-scout run --scope ./examples/scope.toml --out ./assets.jsonl` exits `0` and writes valid JSONL.
- Missing scope exits non-zero.
- Scope with no include rules exits non-zero.
- Scope with non-deny default decision exits non-zero.
- Discovery output contains only allowed hosts/URLs.
- Asset output conforms to expected schema.
- Aether-Link integration calls `/health`, `/configs/current`, and `/assets` with token support.

## Resolved Decisions
- Passive discovery stays enabled by default.
- CIDR scope is validation-only for MVP.
- Primary asset JSONL contains accepted assets only.
- Rejected candidates are written only when `--audit-log` is provided.
- Active polling uses run-level request throttling.
- Aether-Link asset submission uses bounded batches.

## Open Questions
None.
