import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aether_scout.cli import main
from aether_scout.models.asset import Asset
from aether_scout.audit import rejected_candidate


class CliTests(unittest.TestCase):
    def test_validate_scope(self):
        self.assertEqual(main(["validate-scope", "--scope", "./examples/scope.toml"]), 0)

    @patch("aether_scout.cli.discover_assets_with_audit")
    def test_run_writes_accepted_assets_and_audit_log(self, discover):
        discover.return_value = (
            [Asset(program_id="p1", host="api.example.com")],
            [],
            [rejected_candidate("admin.example.com", "subfinder", "host_out_of_scope")],
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "assets.jsonl"
            audit = Path(tmp) / "rejected.jsonl"
            code = main(["run", "--scope", "./examples/scope.toml", "--out", str(out), "--audit-log", str(audit)])

            self.assertEqual(code, 0)
            accepted_rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            rejected_rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(accepted_rows, [{"program_id": "p1", "host": "api.example.com", "discovered_by": "aether-scout", "confidence": 0.5}])
        self.assertEqual(rejected_rows[0]["candidate"], "admin.example.com")
        self.assertEqual(rejected_rows[0]["reason"], "host_out_of_scope")

    def test_missing_scope_exits_nonzero(self):
        self.assertEqual(main(["run"]), 1)

    def test_bad_scope_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.toml"
            path.write_text(
                'program_id = "p1"\ndefault_decision = "allow"\n[[rules]]\ntype = "include"\npattern = "*.example.com"\n',
                encoding="utf-8",
            )
            self.assertEqual(main(["run", "--scope", str(path)]), 1)


if __name__ == "__main__":
    unittest.main()
