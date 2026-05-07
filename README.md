# Aether-Scout

Aether-Scout is conservative recon/discovery for Aether bug bounty automation. It reads approved scope, discovers assets, writes JSONL, and can post candidates to Aether-Link.

It does not generate payloads, execute exploit tests, decide final scope, classify final vulnerabilities, create Probe jobs, auto-submit reports, or perform destructive testing.

## Commands

```bash
aether-scout run --scope ./examples/scope.toml --out ./assets.jsonl
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

## Discovery

Default flow uses approved root domains only:

- passive subdomain discovery through `subfinder`, when installed
- DNS resolution through `dnsx`, with local resolver fallback
- HTTP service probing through `httpx`, when installed
- robots.txt and sitemap.xml path inventory
- AI/MCP surface indicators such as `/mcp`, `/api/mcp`, `/openapi.json`, and `/.well-known/ai-plugin.json`
- asset deduplication before output or Link submission

No deep crawl, fuzzing, vulnerability templates, payload generation, DoS, spam, credential stuffing, persistence, malware, or exfiltration behavior is included.

## Environment

See `.env.example`.

## Migration Note

Older Zero-Flow recon/discovery naming maps here as Aether-Scout. New code, package names, Docker services, and CLI commands use Aether-Scout naming.
