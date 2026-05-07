# Implementation Plan: Aether-Scout

## Overview
Aether-Scout already has a Python CLI scaffold, scope model, discovery orchestrator, Link client, and basic tests. This plan turns the scaffold into a conservative, spec-compliant discovery service by hardening scope enforcement, asset schema behavior, tool wrappers, Link integration, CLI smoke coverage, and documentation.

## Architecture Decisions
- Keep runtime dependency-free by default. Use Python standard library and optional external binaries only through `aether_scout/tools/`.
- Fail closed on scope ambiguity. Scope validation happens before discovery, and every candidate host/URL is filtered again before output.
- Keep Aether-Link as policy owner. Aether-Scout posts assets only; it does not create Aether-Probe jobs or classify final vulnerabilities.
- Treat external recon tools as optional. Missing `subfinder`, `dnsx`, or `httpx` should log and continue with conservative fallbacks where possible.
- Passive discovery modules stay enabled by default because they do not poll target systems. Active polling modules such as HTTP probing, robots/sitemap fetches, and MCP indicator checks require scope gates and rate limiting.
- CIDR rules are validation-only for MVP. Aether-Scout may use CIDR entries to confirm that a discovered hostname resolves to an approved address, but it must not actively enumerate or scan CIDR ranges.
- Primary `--out` JSONL contains accepted assets only. Rejected candidates go to an explicit `--audit-log rejected.jsonl` output with structured rejection reasons.
- Basic request throttling is required in MVP for network reliability and upstream rate-limit compliance. Do not defer `requests_per_minute` enforcement.
- Aether-Link asset submission uses chunked batch requests, targeting 50-100 assets per request, to reduce local bridge overhead and ingestion bottlenecks.
- Prefer small vertical slices. Each task should leave CLI/tests working.

## Dependency Graph
```text
Scope model and validation
    |
    +-- Scope loader from TOML and Aether-Link
    |       |
    |       +-- Discovery candidate filtering
    |       |       |
    |       |       +-- Tool wrappers
    |       |       |       |
    |       |       |       +-- Asset builder and dedupe
    |       |       |               |
    |       |       |               +-- CLI run output
    |       |       |                       |
    |       |       |                       +-- Aether-Link post flow
    |       |       |
    |       |       +-- CLI smoke tests
    |       |
    |       +-- Link config ingestion tests
    |
    +-- Negative safety tests
```

## Task List

### Phase 1: Foundation Safety

## Task 1: Harden Scope Semantics
**Description:** Confirm host, wildcard, URL-prefix, exclude, review, and CIDR behavior matches spec. CIDR rules are validation-only for MVP: they may approve a resolved IP for a discovered hostname, but must never trigger CIDR enumeration or active IP scanning.

**Acceptance criteria:**
- [x] Empty scope and non-deny scope raise clear errors.
- [x] Exclude rules override include rules.
- [x] URL include rules restrict same-host paths by prefix.
- [x] CIDR rules validate resolved candidate IPs without enumerating or actively scanning CIDR ranges.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_scope`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** None

**Files likely touched:**
- `aether_scout/models/scope.py`
- `tests/test_scope.py`

**Estimated scope:** S

## Task 2: Cover Scope Loading Paths
**Description:** Add tests for local TOML parsing and Aether-Link current config payload shapes so run inputs are predictable.

**Acceptance criteria:**
- [x] `scope.toml` fixtures parse include/exclude rules correctly.
- [x] `scope_from_link_current` handles `scope`, `current_scope`, direct `rules`, and empty configs.
- [x] Empty Link config produces invalid scope that refuses run.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_scope_loader`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Task 1

**Files likely touched:**
- `aether_scout/scope_loader.py`
- `tests/test_scope_loader.py`
- `examples/scope.toml`

**Estimated scope:** S

### Checkpoint: Foundation Safety
- [x] `python -m unittest discover -s tests` passes.
- [x] Invalid scope fails closed.
- [x] Scope behavior documented by tests before discovery changes.

### Phase 2: Asset and Discovery Core

## Task 3: Validate Asset Schema and Dedupe
**Description:** Ensure generated assets conform to `spec.md`, omit only empty fields, preserve confidence, dedupe by stable host/URL identity, and keep accepted assets separate from rejected audit records.

**Acceptance criteria:**
- [x] `Asset.to_dict()` output matches expected JSON fields.
- [x] Dedupe keeps one asset per stable key without dropping higher-confidence metadata.
- [x] Asset builder sets scheme, host, port, status, title, technologies, paths, methods, and metadata consistently.
- [x] Rejected candidate records include candidate value, source module, rejection reason, scope rule context, and timestamp.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_asset`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Task 1

**Files likely touched:**
- `aether_scout/models/asset.py`
- `aether_scout/asset_builder.py`
- `aether_scout/dedupe.py`
- `aether_scout/audit.py`
- `tests/test_asset.py`

**Estimated scope:** M

## Task 4: Harden Tool Wrapper Parsing
**Description:** Make passive and active wrapper parsing deterministic with mocked command output. Passive modules remain enabled by default. Active polling modules must require scope-filtered inputs and pass through the shared throttling path.

**Acceptance criteria:**
- [x] `subfinder` output parsing returns unique allowed host candidates.
- [x] `dnsx` output parsing captures A/AAAA/CNAME where available.
- [x] `httpx` output parsing captures URL, status, title, server, content type, redirects, TLS metadata.
- [x] Missing tool behavior is logged and safe.
- [x] Passive discovery runs by default without target polling.
- [x] Active HTTP probing is skipped or throttled when policy/settings require it.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_tools`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Task 3

**Files likely touched:**
- `aether_scout/tools/common.py`
- `aether_scout/tools/subfinder.py`
- `aether_scout/tools/dnsx.py`
- `aether_scout/tools/httpx.py`
- `aether_scout/throttle.py`
- `tests/test_tools.py`

**Estimated scope:** M

## Task 5: Verify Conservative Path Discovery
**Description:** Test `robots_sitemap` and `mcp_detector` with mocked HTTP responses so Aether-Scout inventories interesting paths without crawling deeply or testing vulnerabilities. These active fetches must use shared request throttling.

**Acceptance criteria:**
- [x] `robots.txt` and `sitemap.xml` parsing returns conservative path inventory.
- [x] MCP detector checks only configured indicator paths.
- [x] Network errors and non-200 responses degrade cleanly.
- [x] Detector metadata makes no vulnerability claims.
- [x] Robots, sitemap, and MCP indicator checks use rate limiting.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_path_discovery`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Task 4

**Files likely touched:**
- `aether_scout/tools/robots.py`
- `aether_scout/tools/sitemap.py`
- `aether_scout/tools/mcp_detector.py`
- `aether_scout/throttle.py`
- `tests/test_path_discovery.py`

**Estimated scope:** M

### Checkpoint: Discovery Core
- [x] `python -m unittest discover -s tests` passes.
- [x] Discovery modules work with mocked external tools and mocked HTTP.
- [x] No task introduced required runtime dependencies.

### Phase 3: End-to-End CLI and Link Flow

## Task 6: Add CLI Smoke Tests
**Description:** Cover `validate-scope`, `run --scope`, missing scope, bad scope, accepted JSONL output, and rejected-candidate audit JSONL using local fixtures.

**Acceptance criteria:**
- [x] `validate-scope` returns `0` for example scope.
- [ ] `run --scope --out` writes valid JSONL.
- [ ] `run --scope --out --audit-log` writes rejected candidates with reasons to audit JSONL.
- [ ] Primary `--out` contains accepted assets only.
- [x] Missing scope exits non-zero with clear error.
- [x] Bad default decision exits non-zero.

**Verification:**
- [ ] Tests pass: `python -m unittest tests.test_cli`
- [x] Manual check: `aether-scout validate-scope --scope ./examples/scope.toml`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 2, 3, 4, 5

**Files likely touched:**
- `aether_scout/cli.py`
- `aether_scout/audit.py`
- `tests/test_cli.py`
- `examples/scope.toml`

**Estimated scope:** M

## Task 7: Test Aether-Link Client Contract
**Description:** Verify Link client requests, token header, chunked batch asset submission, JSON body encoding, response parsing, and HTTP error messages.

**Acceptance criteria:**
- [x] `GET /health` and `GET /configs/current` use expected paths.
- [ ] `POST /assets` sends asset payloads in bounded chunks of 50-100 records per request.
- [ ] Batch size is configurable with safe default and validation.
- [x] `Authorization: Bearer ...` is sent when token exists.
- [x] HTTP errors include method, path, status code, and response body.

**Verification:**
- [ ] Tests pass: `python -m unittest tests.test_link_client`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Task 3

**Files likely touched:**
- `aether_scout/link_client.py`
- `tests/test_link_client.py`

**Estimated scope:** S

## Task 8: Add Run-to-Link Integration Test
**Description:** Add local mocked Link server test for `aether-scout run --link-url`, covering `/health`, `/configs/current`, asset discovery, scope-filtered assets, and chunked `/assets` submission.

**Acceptance criteria:**
- [x] CLI fetches scope from Link when no local scope is provided.
- [x] CLI checks Link health before discovery.
- [ ] CLI posts discovered assets to `/assets` in chunks.
- [x] Posted assets are still scope-filtered.
- [ ] Mock server observes chunk sizes within configured limits.

**Verification:**
- [ ] Tests pass: `python -m unittest tests.test_link_run`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 6, 7

**Files likely touched:**
- `aether_scout/cli.py`
- `tests/test_link_run.py`

**Estimated scope:** M

### Checkpoint: End-to-End
- [x] `python -m unittest discover -s tests` passes.
- [ ] Local scope run works.
- [ ] Mock Aether-Link run works.
- [ ] JSONL output validates.

### Phase 4: Configuration and Release Readiness

## Task 9: Enforce Settings and Rate Defaults
**Description:** Test environment variable parsing and enforce request-rate/concurrency settings. MVP must include basic throttling, such as token bucket or sleep-delay control, for active polling modules.

**Acceptance criteria:**
- [x] Environment variables map to `ScoutSettings` correctly.
- [x] Invalid integer values fail clearly or use documented defaults.
- [ ] Passive-only behavior is tested.
- [ ] `AETHER_SCOUT_REQUESTS_PER_MINUTE` is enforced for HTTP, robots/sitemap, and MCP indicator requests.
- [ ] `AETHER_SCOUT_MAX_CONCURRENT_PROBES` is bounded and respected by active probes.
- [ ] Passive discovery remains enabled by default unless explicitly disabled by config.

**Verification:**
- [ ] Tests pass: `python -m unittest tests.test_config`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Task 6

**Files likely touched:**
- `aether_scout/config.py`
- `aether_scout/discovery.py`
- `aether_scout/throttle.py`
- `tests/test_config.py`

**Estimated scope:** S

## Task 10: Align Docs and Examples
**Description:** Update README, `.env.example`, Docker example, and migration wording so docs match CLI, env vars, and safety boundaries.

**Acceptance criteria:**
- [x] README commands match working CLI commands.
- [x] `.env.example` includes spec env vars with safe placeholder values.
- [x] Docker service/image/package names use Aether-Scout naming.
- [x] No new Zero-Flow naming exists outside migration note.
- [ ] README documents `--audit-log`, accepted-only `--out`, CIDR validation-only behavior, passive-default behavior, throttling, and batched Link submission.

**Verification:**
- [ ] Search passes: `rg "Zero-Flow|zero-flow|ZERO_FLOW" .`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 6, 9

**Files likely touched:**
- `README.md`
- `.env.example`
- `docker-compose.example.yml`
- `Dockerfile`
- `spec.md`

**Estimated scope:** S

## Task 11: Final Safety Regression Pass
**Description:** Add or tighten tests for explicit never-do boundaries: no Probe jobs, no payload generation, no vulnerability classification, no deep crawl/fuzz defaults.

**Acceptance criteria:**
- [x] No code path references Aether-Probe job creation.
- [x] No payload/test execution modules exist in Aether-Scout.
- [x] MCP detection remains indicator-only.
- [x] Default run does not deep crawl or fuzz paths.

**Verification:**
- [x] Search passes: `rg "payload|exploit|vulnerability|Aether-Probe|probe job|fuzz|crawl" aether_scout tests README.md spec.md plan.md`
- [x] Full suite passes: `python -m unittest discover -s tests`
- [x] Manual review confirms matches are boundary docs/tests only.

**Dependencies:** Tasks 5, 10

**Files likely touched:**
- `tests/test_safety_boundaries.py`
- `README.md`
- `spec.md`

**Estimated scope:** S

### Checkpoint: Complete
- [x] All tests pass: `python -m unittest discover -s tests`.
- [ ] CLI local-scope flow works.
- [ ] Mock Aether-Link flow works.
- [ ] Docs match behavior.
- [x] Safety boundaries reviewed.
- [ ] Human reviewed and approved plan before implementation.

## Parallelization Opportunities
- Tasks 1 and 7 can run in parallel after plan approval.
- Tasks 3 and 7 can run in parallel because asset internals and Link transport are separate.
- Tasks 4 and 5 can run in parallel after Task 3 if wrapper ownership is split by file.
- Task 10 can start after CLI command behavior stabilizes in Task 6.

Must be sequential:
- Task 2 depends on Task 1 scope semantics.
- Task 6 depends on core discovery/assets being stable.
- Task 8 depends on CLI and Link client coverage.
- Task 11 should be last.

## Risks and Mitigations
| Risk | Impact | Mitigation |
|------|--------|------------|
| Scope rule ambiguity allows out-of-scope probing | High | Fail closed, test exclude/review/URL-prefix behavior, filter before output |
| External tool output changes | Medium | Keep parsers tolerant, test multiple line formats, log unknown rows |
| Network-heavy tests become flaky | Medium | Use mocked subprocess and HTTP responses for unit tests |
| Optional tools become hidden hard dependencies | Medium | Test missing-binary paths and fallback behavior |
| Link API shape differs from local assumptions | Medium | Keep `scope_from_link_current` tolerant, document supported payload shapes |
| Confidence scoring becomes inconsistent | Low | Centralize scoring rules or test builder outputs |
| Audit output leaks accepted/rejected records into wrong file | Medium | Keep accepted asset writer and audit writer separate, with JSONL tests |
| Throttling slows local tests | Low | Inject clock/sleep dependency for deterministic unit tests |
| Batch submission partially fails | Medium | Return per-chunk results and surface failed chunk context in errors |

## Resolved Decisions
- Passive discovery remains enabled by default. Active polling modules require scope checks and rate limiting.
- CIDR scope is validation-only for MVP. No active CIDR enumeration or IP-block scanning.
- Primary `--out` JSONL contains accepted assets only. Rejected candidates go to `--audit-log`.
- `requests_per_minute` throttling is required in MVP.
- `POST /assets` uses bounded chunked batch submission, defaulting to 50-100 assets per request.

## Open Questions
None.
