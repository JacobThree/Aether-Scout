from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse
import fnmatch
import ipaddress


@dataclass(slots=True)
class ScopeRule:
    pattern: str
    rule_type: str = "include"
    notes: str | None = None

    @property
    def scope_type(self) -> str:
        return detect_scope_type(self.pattern)


@dataclass(slots=True)
class ScopeConfig:
    program_id: str
    default_decision: str = "deny"
    rules: list[ScopeRule] = field(default_factory=list)

    def include_rules(self) -> list[ScopeRule]:
        return [r for r in self.rules if r.rule_type == "include"]

    def cidr_include_rules(self) -> list[ScopeRule]:
        return [r for r in self.include_rules() if r.scope_type == "cidr"]

    def root_domains(self) -> list[str]:
        roots: list[str] = []
        seen: set[str] = set()
        for rule in self.include_rules():
            host = seed_host_from_pattern(rule.pattern)
            if host and host not in seen:
                seen.add(host)
                roots.append(host)
        return roots

    def validate_for_run(self) -> None:
        if self.default_decision != "deny":
            raise ValueError("scope default_decision must be deny")
        if not self.include_rules():
            raise ValueError("scope has no include rules")

    def is_host_allowed(self, hostname: str) -> bool:
        host = (hostname or "").lower().rstrip(".")
        if not host:
            return False
        decision = self.default_decision
        for rule in self.rules:
            if not _host_matches_pattern(host, rule.pattern):
                continue
            if rule.rule_type == "exclude":
                return False
            if rule.rule_type == "requires_review":
                decision = "review"
            if rule.rule_type == "include" and decision != "review":
                decision = "allow"
        return decision == "allow"

    def is_url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if not parsed.hostname or not self.is_host_allowed(parsed.hostname):
            return False

        explicit_url_rules = [
            r for r in self.include_rules()
            if detect_scope_type(r.pattern) == "url"
            and (urlparse(r.pattern).hostname or "").lower() == parsed.hostname.lower()
        ]
        if not explicit_url_rules:
            return True
        candidate_path = parsed.path or "/"
        return any(candidate_path.startswith(urlparse(r.pattern).path or "/") for r in explicit_url_rules)

    def is_resolved_ip_allowed(self, ip: str | None) -> bool:
        if not ip:
            return True
        try:
            candidate = ipaddress.ip_address(ip)
        except ValueError:
            return False

        cidr_rules = [r for r in self.rules if r.scope_type == "cidr"]
        if not cidr_rules:
            return True

        allowed = False
        for rule in cidr_rules:
            network = ipaddress.ip_network(rule.pattern, strict=False)
            if candidate not in network:
                continue
            if rule.rule_type == "exclude":
                return False
            if rule.rule_type == "include":
                allowed = True
        return allowed


def detect_scope_type(value: str) -> str:
    v = value.strip()
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    if v.startswith("*."):
        return "wildcard"
    try:
        ipaddress.ip_network(v, strict=False)
        return "cidr"
    except ValueError:
        return "domain"


def normalize_scope_values(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def seed_host_from_pattern(pattern: str) -> str | None:
    scope_type = detect_scope_type(pattern)
    if scope_type == "wildcard":
        return pattern.strip().lower().removeprefix("*.")
    if scope_type == "domain":
        return pattern.strip().lower()
    if scope_type == "url":
        return urlparse(pattern).hostname
    return None


def _host_matches_pattern(host: str, pattern: str) -> bool:
    raw = pattern.strip().lower()
    scope_type = detect_scope_type(raw)
    if scope_type == "url":
        raw_host = (urlparse(raw).hostname or "").lower()
        return host == raw_host
    if scope_type == "wildcard":
        base = raw.removeprefix("*.")
        return host == base or host.endswith(f".{base}")
    if scope_type == "domain":
        if "*" in raw:
            return fnmatch.fnmatch(host, raw)
        return host == raw or host.endswith(f".{raw}")
    return False
