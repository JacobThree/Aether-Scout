import json
import tempfile
import unittest
from pathlib import Path

from aether_scout.cli import main
from aether_scout.models.scope import ScopeConfig, ScopeRule
from aether_scout.request_shapes import import_request_shapes


class RequestShapeTests(unittest.TestCase):
    def scope(self) -> ScopeConfig:
        return ScopeConfig(program_id="p1", rules=[ScopeRule("*.example.com", "include")])

    def test_imports_schema_metadata_and_redacts_secrets(self):
        records = [{
            "method": "POST",
            "url": "https://app.example.com/api/chat",
            "headers": {"authorization": "Bearer secret", "x-safe": "ok"},
            "request": {"prompt": "hi", "tenant_id": "t1", "workspace_id": "w1"},
            "response": {"answer": "hello", "sources": [{"url": "doc"}], "citations": []},
            "content_type": "text/event-stream",
        }]

        schemas, rejected = import_request_shapes(records, self.scope())

        self.assertEqual(rejected, [])
        schema = schemas[0].to_dict()
        self.assertEqual(schema["prompt_key"], "request.prompt")
        self.assertEqual(schema["tenant_key"], "request.tenant_id")
        self.assertEqual(schema["workspace_key"], "request.workspace_id")
        self.assertEqual(schema["response_text_path"], "response.answer")
        self.assertEqual(schema["sources_path"], "response.sources")
        self.assertEqual(schema["citations_path"], "response.citations")
        self.assertTrue(schema["streaming"])
        self.assertEqual(schema["metadata"]["headers"]["authorization"], "[REDACTED]")
        self.assertEqual(schema["metadata"]["headers"]["x-safe"], "ok")

    def test_rejects_out_of_scope_and_malformed_records(self):
        schemas, rejected = import_request_shapes([{"url": "https://evil.test/api/chat"}, "bad"], self.scope())

        self.assertEqual(schemas, [])
        self.assertEqual([row.candidate_type for row in rejected], ["schema", "schema"])
        self.assertEqual(rejected[0].reason, "url_out_of_scope")
        self.assertEqual(rejected[1].reason, "malformed_record")

    def test_detects_upload_relationship(self):
        schemas, rejected = import_request_shapes([{
            "method": "POST",
            "url": "https://app.example.com/api/documents/upload",
            "content_type": "multipart/form-data",
            "request": {"file": "document.pdf"},
            "response": {"text": "ok"},
        }], self.scope())

        self.assertEqual(rejected, [])
        self.assertEqual(schemas[0].upload_endpoint, "https://app.example.com/api/documents/upload")

    def test_cli_import_request_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            recording = Path(tmp) / "recording.json"
            out = Path(tmp) / "schemas.jsonl"
            audit = Path(tmp) / "audit.jsonl"
            recording.write_text(json.dumps({"requests": [
                {"url": "https://app.example.com/api/chat", "request": {"prompt": "hi"}},
                {"url": "https://evil.test/api/chat", "request": {"prompt": "hi"}},
            ]}), encoding="utf-8")

            code = main(["import-request-shapes", "--input", str(recording), "--scope", "./examples/scope.toml", "--out", str(out), "--audit-log", str(audit)])

            self.assertEqual(code, 0)
            schema_rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            audit_rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(len(schema_rows), 1)
        self.assertEqual(schema_rows[0]["url"], "https://app.example.com/api/chat")
        self.assertEqual(audit_rows[0]["candidate_type"], "schema")


if __name__ == "__main__":
    unittest.main()
