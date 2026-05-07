from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse
import json
import shutil
import subprocess


@dataclass(slots=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    started_at: str
    completed_at: str


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def run_cmd(cmd: list[str], *, input_text: str | None = None, timeout: int = 10) -> CommandResult:
    started = now_iso()
    try:
        proc = subprocess.run(cmd, input=input_text, text=True, capture_output=True, timeout=timeout, check=False)
        exit_code = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except FileNotFoundError:
        exit_code = 127
        stdout = ""
        stderr = f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + "\ncommand timed out"
    return CommandResult(exit_code=exit_code, stdout=stdout, stderr=stderr, started_at=started, completed_at=now_iso())


def tool_available(path: str) -> bool:
    return shutil.which(path) is not None


def parse_hosts(output: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        token = _first_token(line)
        if token.startswith("http://") or token.startswith("https://"):
            host = urlparse(token).hostname
            if host:
                token = host
        token = token.lower().rstrip(".")
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    return out


def parse_urls(output: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        token = _first_token(line)
        if token.startswith("http://") or token.startswith("https://"):
            if token not in seen:
                seen.add(token)
                out.append(token)
    return out


def iter_json_lines(output: str):
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _first_token(line: str) -> str:
    value = line.strip()
    return value.split()[0] if value else ""
