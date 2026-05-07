You are generating a new repo called Aether-Scout.

Aether-Scout replaces the older Zero-Flow naming. Do not use the name Zero-Flow in new code, docs, Docker services, package names, or README except possibly in a migration note.

Aether-Scout is the recon/discovery engine for the Aether bug bounty automation stack.

The four repos are:

- Aether-Strategist: scope/config compiler
- Aether-Scout: recon/discovery
- Aether-Link: brain/orchestrator/policy/reporting
- Aether-Probe: controlled payload/test execution engine

Aether-Scout reads approved scope and discovers assets.

Aether-Scout does not:
- generate payloads
- execute exploit tests
- decide final scope
- classify final vulnerabilities
- auto-submit reports
- perform destructive testing
- run DoS, spam, credential stuffing, persistence, malware, or data exfiltration behavior

Aether-Scout should:
- load scope from Aether-Link or local config
- perform passive-first recon
- discover subdomains, live HTTP services, interesting paths, AI/MCP surfaces, and technology metadata
- deduplicate assets
- post assets to Aether-Link
- mark confidence levels
- be conservative when scope is ambiguous
- avoid aggressive crawling by default

Primary flow:

1. Aether-Link imports scope config from Aether-Strategist.
2. Aether-Scout fetches current scope from Aether-Link GET /configs/current or reads local scope.toml.
3. Aether-Scout performs discovery only against allowed scope patterns.
4. Aether-Scout probes discovered candidates conservatively.
5. Aether-Scout posts discovered assets to Aether-Link POST /assets.
6. Aether-Link decides in_scope, out_of_scope, or needs_human_review.
7. Aether-Scout does not create jobs directly for Aether-Probe.

Recommended repo structure:

aether-scout/
  README.md
  pyproject.toml
  docker-compose.example.yml
  .env.example
  aether_scout/
    main.py
    config.py
    cli.py
    link_client.py
    scope_loader.py
    discovery.py
    dedupe.py
    asset_builder.py
    tools/
      subfinder.py
      httpx.py
      dnsx.py
      robots.py
      sitemap.py
      mcp_detector.py
      tech_fingerprint.py
    models/
      scope.py
      asset.py
  examples/
    scope.toml
    assets.jsonl

CLI commands:

aether-scout run --scope ./scope.toml --out ./assets.jsonl

aether-scout run --link-url http://localhost:8080

aether-scout validate-scope --scope ./scope.toml

aether-scout push-assets --assets ./assets.jsonl --link-url http://localhost:8080

Discovery modules:

1. scope_loader
- Loads scope.toml.
- Extracts in-scope domain and URL patterns.
- Refuses to run if scope is empty.
- Refuses to run if default_decision is not deny.

2. passive_discovery
- Optional passive subdomain sources.
- Should be conservative and configurable.

3. subdomain_discovery
- Wrap tools like subfinder if available.
- Must only run against approved root domains.

4. http_probe
- Wrap tools like httpx if available.
- Finds live services.
- Captures status code, title, server, content type, redirects, TLS info.

5. dns_probe
- Wrap tools like dnsx if available.
- Resolves domains.
- Captures A, AAAA, CNAME where useful.

6. robots_sitemap
- Checks robots.txt and sitemap.xml.
- Extracts interesting paths conservatively.
- Does not crawl deeply by default.

7. mcp_detector
- Looks for likely AI/MCP surfaces.
- Examples of indicators:
  - /.well-known/ai-plugin.json
  - /mcp
  - /api/mcp
  - /tools
  - /openapi.json
  - /swagger.json
  - /.well-known/openapi.json
- This is discovery only, not testing.

8. tech_fingerprint
- Records visible technology hints.
- Does not make vulnerability claims.

Asset output schema:

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

Aether-Scout to Aether-Link connection:

Aether-Scout should call:

GET /configs/current
- fetches active program and scope summary.

POST /assets
- posts discovered assets.

GET /health
- verifies Aether-Link is reachable.

Recommended environment variables:

AETHER_LINK_URL=http://aether-link:8080
AETHER_API_TOKEN=change_me
AETHER_SCOUT_WORKER_ID=scout_local_001
AETHER_SCOUT_SCOPE_FILE=/shared/configs/current/scope.toml
AETHER_SCOUT_OUTPUT_FILE=/shared/assets/assets.jsonl
AETHER_SCOUT_PASSIVE_ONLY=false
AETHER_SCOUT_MAX_CONCURRENT_PROBES=5
AETHER_SCOUT_REQUESTS_PER_MINUTE=30
AETHER_SCOUT_TIMEOUT_SECONDS=10
AETHER_SCOUT_USER_AGENT=Aether-Scout authorized-recon

Rules Aether-Scout must enforce:

- Do not run without scope.
- Do not run if scope has no include rules.
- Do not run against out-of-scope patterns.
- Do not deep crawl by default.
- Do not fuzz paths by default.
- Do not run vulnerability templates by default.
- Do not generate payloads.
- Do not send results directly to Aether-Probe.
- Post everything to Aether-Link for policy handling.
- Treat wildcard scope carefully.
- Mark uncertain discoveries with lower confidence.
- Preserve enough metadata for humans to understand how an asset was discovered.

What code should be moved into Aether-Scout from existing Aether-Link or Aether-Probe:

From Aether-Link:
- subdomain discovery logic
- http probing logic
- DNS probing wrappers
- endpoint inventory generation
- MCP/AI surface detection
- tech fingerprinting
- robots.txt and sitemap parsing
- asset deduplication before submission
- passive recon integrations

From Aether-Probe:
- any target discovery logic
- any code that probes many hosts to find live services
- any code that scans for MCP paths before a job exists
- any code that crawls endpoints broadly
- any code that builds asset inventories

Do not move into Aether-Scout:
- bug bounty brief parsing
- config generation
- policy approval
- job queue
- payload/test execution
- evidence report generation
- final vulnerability classification

Migration note:

If existing code or docs refer to Zero-Flow, rename it to Aether-Scout:
- package name: aether_scout
- Docker service: aether-scout
- image name: aether-scout
- CLI command: aether-scout
- README title: Aether-Scout
- environment variable prefix: AETHER_SCOUT_

Generation goal:

Build Aether-Scout as a conservative recon/discovery service that finds assets and surfaces, then hands them to Aether-Link. It should be boring, scoped, and reliable.