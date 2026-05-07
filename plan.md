# Implementation Plan: Aether-Scout

## Overview
Aether-Scout already has a Python CLI scaffold, scope model, discovery orchestrator, Link client, conservative asset discovery, audit logging, throttling, and basic tests. The completed MVP hardens scope enforcement, asset schema behavior, tool wrappers, Link integration, CLI smoke coverage, and documentation. The next roadmap extends Scout into a scoped AI/RAG surface mapper, request-shape normalizer, viability scorer, and import-only external metadata adapter layer without adding exploit behavior.

## Architecture Decisions
- Keep runtime dependency-free by default. Use Python standard library and optional external binaries only through `aether_scout/tools/`.
- Fail closed on scope ambiguity. Scope validation happens before discovery, and every candidate host/URL is filtered again before output.
- Keep Aether-Link as policy owner. Aether-Scout posts metadata-only assets, surfaces, and schemas; it does not create Aether-Probe jobs or classify final vulnerabilities.
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

Completed MVP
    |
    +-- Surface model and mapper
    |       |
    |       +-- Surface JSONL output and audit records
    |       |       |
    |       |       +-- Link surface push contract
    |
    +-- Request-shape import and normalization
    |       |
    |       +-- Schema JSONL output and audit records
    |       |       |
    |       |       +-- Link schema push contract
    |
    +-- Viability scoring
    |
    +-- Import-only external adapters
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
- [x] `run --scope --out` writes valid JSONL.
- [x] `run --scope --out --audit-log` writes rejected candidates with reasons to audit JSONL.
- [x] Primary `--out` contains accepted assets only.
- [x] Missing scope exits non-zero with clear error.
- [x] Bad default decision exits non-zero.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_cli`
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
- [x] `POST /assets` sends asset payloads in bounded chunks of 50-100 records per request.
- [x] Batch size is configurable with safe default and validation.
- [x] `Authorization: Bearer ...` is sent when token exists.
- [x] HTTP errors include method, path, status code, and response body.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_link_client`
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
- [x] CLI posts discovered assets to `/assets` in chunks.
- [x] Posted assets are still scope-filtered.
- [x] Mock server observes chunk sizes within configured limits.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_link_run`
- [x] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 6, 7

**Files likely touched:**
- `aether_scout/cli.py`
- `tests/test_link_run.py`

**Estimated scope:** M

### Checkpoint: End-to-End
- [x] `python -m unittest discover -s tests` passes.
- [x] Local scope run works.
- [x] Mock Aether-Link run works.
- [x] JSONL output validates.

### Phase 4: Configuration and Release Readiness

## Task 9: Enforce Settings and Rate Defaults
**Description:** Test environment variable parsing and enforce request-rate/concurrency settings. MVP must include basic throttling, such as token bucket or sleep-delay control, for active polling modules.

**Acceptance criteria:**
- [x] Environment variables map to `ScoutSettings` correctly.
- [x] Invalid integer values fail clearly or use documented defaults.
- [x] Passive-only behavior is tested.
- [x] `AETHER_SCOUT_REQUESTS_PER_MINUTE` is enforced for HTTP, robots/sitemap, and MCP indicator requests.
- [x] `AETHER_SCOUT_MAX_CONCURRENT_PROBES` is bounded and respected by active probes.
- [x] Passive discovery remains enabled by default unless explicitly disabled by config.

**Verification:**
- [x] Tests pass: `python -m unittest tests.test_config`
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
- [x] README documents `--audit-log`, accepted-only `--out`, CIDR validation-only behavior, passive-default behavior, throttling, and batched Link submission.

**Verification:**
- [x] Search passes: `rg "Zero-Flow|zero-flow|ZERO_FLOW" .`
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
- [x] CLI local-scope flow works.
- [x] Mock Aether-Link flow works.
- [x] Docs match behavior.
- [x] Safety boundaries reviewed.
- [x] MVP plan implemented.

### Phase 5: Surface Mapping and Metadata Import

## Task 12: Implement Surface Mapper
**Description:** Add metadata-only surface candidates for likely AI/RAG/MCP/copilot/helpdesk/chat surfaces inside approved scope. Surface mapping must not generate payloads, execute exploit tests, classify vulnerabilities, create Probe jobs, or auto-submit reports.

**Acceptance criteria:**
- [ ] Add `Surface` model with `surface_id`, `program_id`, `asset_id`, `surface_type`, `url`, optional `method`, `confidence`, `evidence_metadata`, `indicators`, `scope_status`, and `discovered_at`.
- [ ] Support surface types: `rag_chat`, `ai_chat`, `copilot`, `helpdesk_bot`, `support_assistant`, `mcp_endpoint`, `openapi_schema`, `websocket_chat`, `graphql_ai`, `document_upload`, and `unknown_ai_surface`.
- [ ] Detect indicators from known paths, page text, script names, provided network hints, OpenAPI tags, sitemap paths, and robots paths.
- [ ] Add `aether-scout map-surfaces --scope <scope.toml> --out surfaces.jsonl`.
- [ ] Add `aether-scout push-surfaces --surfaces surfaces.jsonl --link-url <url>`.
- [ ] Scope-filter every candidate before output or Link push.
- [ ] Send out-of-scope surface candidates to audit log, not primary output.

**Verification:**
- [ ] Tests cover accepted surfaces, rejected surfaces, JSONL output, and Link push.
- [ ] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 1-11

**Files likely touched:**
- `aether_scout/models/surface.py`
- `aether_scout/surface_mapper.py`
- `aether_scout/cli.py`
- `aether_scout/link_client.py`
- `aether_scout/audit.py`
- `tests/test_surface_mapper.py`
- `tests/test_link_client.py`

**Estimated scope:** M

## Task 13: Import and Normalize Request Shapes
**Description:** Import recorder/Burp/manual request-shape metadata and convert it into conservative schema/surface candidates. Scout must not replay requests or test vulnerabilities.

**Acceptance criteria:**
- [ ] Add `aether-scout import-request-shapes --input recording.json --out schemas.jsonl`.
- [ ] Add `aether-scout push-schemas --schemas schemas.jsonl --link-url <url>`.
- [ ] Detect metadata only: `prompt_key`, `tenant_key`, `workspace_key`, `org_key`, `response_text_path`, `sources_path`, `citations_path`, streaming mode, and upload endpoint relationship.
- [ ] Redact secrets before output or Link push.
- [ ] Preserve confidence and ambiguity fields.
- [ ] Scope-filter imported records before output or Link submission.
- [ ] Submit metadata only to Link `/schemas` or `/surfaces`.

**Verification:**
- [ ] Tests cover sample recordings, redaction, schema output, surface output, and rejected records.
- [ ] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Task 12 can run in parallel if write scope is split; Link schema push depends on Task 15.

**Files likely touched:**
- `aether_scout/models/schema.py`
- `aether_scout/request_shapes.py`
- `aether_scout/cli.py`
- `aether_scout/link_client.py`
- `tests/test_request_shapes.py`

**Estimated scope:** M

## Task 14: Add AI/RAG Surface Viability Scoring
**Description:** Rank discovered surfaces by likely value for bounty-relevant AI/RAG testing without running exploit tests or making vulnerability claims.

**Acceptance criteria:**
- [ ] Add rule-based scoring factors for AI/chat indicators, RAG/document/source indicators, tenant/workspace/team UI indicators, upload/document management indicators, citation/source UI indicators, auth-required surfaces, API schema confidence, and program policy status.
- [ ] Output `viability_score` from `0.0` to `1.0`.
- [ ] Output `recommended_next_step`, `blockers`, and `evidence_metadata`.
- [ ] Add `aether-scout score-surfaces --surfaces surfaces.jsonl --out scored_surfaces.jsonl`.
- [ ] Label fatal blockers clearly instead of hiding them inside score.
- [ ] Keep Link as final authority and do not create Probe jobs.

**Verification:**
- [ ] Tests cover high, medium, low, and fatal-blocker scoring.
- [ ] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Task 12

**Files likely touched:**
- `aether_scout/scoring.py`
- `aether_scout/cli.py`
- `tests/test_scoring.py`

**Estimated scope:** S

## Task 15: Polish Link Push Contracts for Assets, Surfaces, and Schemas
**Description:** Extend Link client push support beyond assets so Scout can send metadata-only assets, surfaces, and schemas in bounded chunks with clear errors.

**Acceptance criteria:**
- [ ] Link client supports `GET /health`, `GET /configs/current`, `POST /assets`, `POST /surfaces`, and `POST /schemas`.
- [ ] Assets, surfaces, and schemas send in bounded chunks of 50-100 records.
- [ ] Batch size remains configurable with safe validation.
- [ ] `Authorization: Bearer ...` is sent when token exists.
- [ ] HTTP errors include method, path, status code, and response body.
- [ ] Raw credentials are not logged.

**Verification:**
- [ ] Tests pass: `python -m unittest tests.test_link_client`
- [ ] Local mocked Link server covers asset, surface, and schema push.
- [ ] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 7, 12, 13

**Files likely touched:**
- `aether_scout/link_client.py`
- `tests/test_link_client.py`
- `tests/test_link_run.py`

**Estimated scope:** S

## Task 16: Add Import-Only External Tool Adapters
**Description:** Import asset/surface/schema metadata from external tools without executing target requests by default.

**Acceptance criteria:**
- [ ] Add adapter interface with `adapter_name`, `supported_input_format`, `output_type`, and `safety_mode: import_only`.
- [ ] Add MVP adapters for httpx JSONL, subfinder text, OpenAPI JSON, generic URL list, and optional Burp sitemap/HAR metadata.
- [ ] Add `aether-scout adapters list`.
- [ ] Add `aether-scout adapters import --adapter httpx --input file.jsonl --out assets.jsonl`.
- [ ] Scope-filter all imported candidates.
- [ ] Send rejected candidates to audit log.
- [ ] Deduplicate imported records.
- [ ] Malformed input fails clearly or emits audit records where appropriate.

**Verification:**
- [ ] Tests cover scope filtering, malformed input, duplicate records, and rejected candidates.
- [ ] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 3, 12, 13

**Files likely touched:**
- `aether_scout/adapters/`
- `aether_scout/cli.py`
- `aether_scout/audit.py`
- `tests/test_adapters.py`

**Estimated scope:** M

## Task 17: Improve Rejected Candidate Audit Log for Assets, Surfaces, and Schemas
**Description:** Expand audit records so operators can understand refused candidates across all output types without mixing rejected records into primary output.

**Acceptance criteria:**
- [ ] Rejected records include candidate value, candidate type, source module, rejection reason, matching scope rule if available, timestamp, confidence, and ambiguity.
- [ ] `--audit-log rejected.jsonl` works for asset, surface, schema, and adapter import flows.
- [ ] Primary `--out` contains accepted assets/surfaces/schemas only.
- [ ] Rejected candidates are never treated as findings.
- [ ] Audit records cover out-of-scope hosts, excluded paths, ambiguous candidates, malformed URLs, and duplicates.

**Verification:**
- [ ] Tests cover rejected records for asset, surface, schema, and adapter flows.
- [ ] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 12, 13, 16

**Files likely touched:**
- `aether_scout/audit.py`
- `aether_scout/cli.py`
- `tests/test_audit.py`

**Estimated scope:** S

## Task 18: Expand Conservative AI Path Indicators
**Description:** Add a small curated AI/RAG/MCP indicator list checked only against already accepted scoped base URLs using shared throttling.

**Acceptance criteria:**
- [ ] Add indicators for `/api/chat`, `/chat`, `/assistant`, `/copilot`, `/ask`, `/api/ask`, `/api/ai`, `/api/search`, `/mcp`, `/api/mcp`, `/.well-known/ai-plugin.json`, and `/openapi.json`.
- [ ] Check indicator paths only against accepted scoped base URLs.
- [ ] Use existing throttling/rate-limit path.
- [ ] Record indicators as metadata, not vulnerabilities.
- [ ] Missing paths and 404s do not create noisy errors.
- [ ] Positive indicators create surface candidates only.

**Verification:**
- [ ] Tests use mocked HTTP responses for positive, negative, and error cases.
- [ ] Full suite passes: `python -m unittest discover -s tests`

**Dependencies:** Tasks 12, 9

**Files likely touched:**
- `aether_scout/surface_mapper.py`
- `aether_scout/tools/mcp_detector.py`
- `aether_scout/throttle.py`
- `tests/test_surface_mapper.py`

**Estimated scope:** S

### Checkpoint: Surface Metadata Roadmap
- [ ] `python -m unittest discover -s tests` passes.
- [ ] Scout outputs metadata-only assets, surfaces, and schemas.
- [ ] Link push works for assets, surfaces, and schemas.
- [ ] Primary outputs contain accepted candidates only.
- [ ] Audit logs contain rejected candidates only.
- [ ] No exploit tests, payload generation, Probe job creation, or vulnerability classification added.

## Parallelization Opportunities
- Tasks 12 and 13 can run in parallel if model/CLI write ownership is coordinated.
- Task 14 can start after Task 12 surface JSONL shape is stable.
- Task 15 can run alongside Tasks 12 and 13 after endpoint payload shapes are agreed.
- Task 16 can run after existing asset import patterns and new surface/schema models are stable.
- Task 17 should follow Tasks 12, 13, and 16 so audit shape covers all candidate types.
- Task 18 can run with Task 12 if path-indicator ownership is assigned clearly.

Must be sequential:
- Completed MVP Tasks 1-11 remain baseline and should stay green before new work merges.
- Task 14 depends on Task 12.
- Task 17 depends on candidate output flows from Tasks 12, 13, and 16.

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
| Surface mapping drifts into vulnerability claims | High | Store indicators/evidence only, add safety-boundary tests, avoid payload strings |
| Request-shape import leaks secrets | High | Central redaction helper with tests for headers, cookies, tokens, and body fields |
| External adapter import becomes active scanning | High | Adapter `safety_mode` is `import_only`; adapters read files only |
| Viability score feels authoritative | Medium | Keep explainable factors, blockers, and non-vulnerability wording in output |

## Resolved Decisions
- Passive discovery remains enabled by default. Active polling modules require scope checks and rate limiting.
- CIDR scope is validation-only for MVP. No active CIDR enumeration or IP-block scanning.
- Primary `--out` JSONL contains accepted assets only. Rejected candidates go to `--audit-log`.
- `requests_per_minute` throttling is required in MVP.
- `POST /assets` uses bounded chunked batch submission, defaulting to 50-100 assets per request.
- New surface/schema flows must stay metadata-only.
- External adapters are import-only by default.
- Viability scoring ranks next-review priority, not vulnerability presence.

## Open Questions
None.
