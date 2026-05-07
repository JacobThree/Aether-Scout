# Aether-Scout

Aether-Scout is conservative recon/discovery for Aether bug bounty automation. It reads approved scope, discovers assets, writes JSONL, and can post candidates to Aether-Link.

It does not generate payloads, execute exploit tests, decide final scope, classify final vulnerabilities, create Probe jobs, auto-submit reports, or perform destructive testing.

## Commands

```bash
aether-scout run --scope ./examples/scope.toml --out ./assets.jsonl --audit-log ./rejected.jsonl
aether-scout run --link-url http://localhost:8080
aether-scout validate-scope --scope ./examples/scope.toml
aether-scout push-assets --assets ./assets.jsonl --link-url http://localhost:8080
```

## Scope Rules

Runs require `default_decision = "deny"` and at least one include rule. Ambiguous or missing scope stops execution.

```toml
program_id = "program_example_001"
default_decision = "deny"

[[rules]]
type = "include"
pattern = "*.example.com"

[[rules]]
type = "exclude"
pattern = "admin.example.com"
```

CIDR rules are validation-only for MVP. Aether-Scout can use CIDR includes/excludes to validate resolved IPs for discovered hostnames, but it does not enumerate or actively scan IP blocks.

## Discovery

Default flow uses approved root domains only:

- passive subdomain discovery through `subfinder`, when installed
- DNS resolution through `dnsx`, with local resolver fallback
- HTTP service probing through `httpx`, when installed and after scope filtering
- robots.txt and sitemap.xml path inventory with request throttling
- AI/MCP surface indicators such as `/mcp`, `/api/mcp`, `/openapi.json`, and `/.well-known/ai-plugin.json`, with request throttling
- asset deduplication before output or Link submission

Passive discovery remains enabled by default because it does not poll target systems. `--passive-only` skips DNS, HTTP, robots/sitemap, and MCP probes.

The primary `--out` file contains accepted assets only. Use `--audit-log ./rejected.jsonl` to write rejected candidates and rejection reasons for scope debugging.

Aether-Link submissions are batched to `/assets` in bounded chunks, defaulting to 50 records per request. Configure with `AETHER_SCOUT_LINK_BATCH_SIZE` up to `100`.

No deep crawl, fuzzing, vulnerability templates, payload generation, DoS, spam, credential stuffing, persistence, malware, or exfiltration behavior is included.

## Environment

See `.env.example`.

## Migration Note

Older Zero-Flow recon/discovery naming maps here as Aether-Scout. New code, package names, Docker services, and CLI commands use Aether-Scout naming.
